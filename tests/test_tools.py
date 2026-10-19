"""Behavioral tests for the tools exposed to the security agent."""

from contextlib import contextmanager
import json
import os
import subprocess
import sys
from pathlib import Path
from threading import Thread
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest
import requests
from werkzeug.serving import make_server, WSGIRequestHandler

from target.LFI_RFI_service import app as file_inclusion_app, PUBLIC_DIR as FILE_INCLUSION_PUBLIC_DIR
from target.LFI_RFI_remote import app as file_inclusion_remote_app
from tools import run_file_inclusion_agent as file_inclusion_agent_launcher
from tools.file_inclusion_probe import scan_lab as scan_file_inclusion_lab

from tools import (
    ALL_TOOLS,
    check_arp_table,
    check_file_inclusion,
    check_idor,
    list_files,
    read_file,
    read_file_around_line,
    run_arp_spoof,
    run_nuclei,
    run_semgrep,
    run_zap_scan,
    test_nosqli_lab as nosqli_lab_tool,
    test_sqli_lab as sqli_lab_tool,
    test_sqli_login as sqli_login_tool,
)

zap_module = import_module("tools.run_zap_scan")
sqli_lab_module = import_module("tools.test_sqli_lab")
arp_table_module = import_module("tools.check_arp_table")


def test_registered_tools_match_tools_with_behavioral_tests():
    tested_tools = (
        check_idor, run_semgrep, sqli_login_tool, read_file, read_file_around_line,
        run_nuclei, run_zap_scan, list_files, sqli_lab_tool,
        check_file_inclusion, nosqli_lab_tool, check_arp_table, run_arp_spoof,
    )

    assert sorted(item.name for item in ALL_TOOLS) == sorted(
        item.name for item in tested_tools
    )


def test_read_file_returns_content_and_metadata(tmp_path):
    source = tmp_path / "example.py"
    source.write_text("first line\nsecond line\n", encoding="utf-8")

    result = read_file.invoke({"path": str(source), "cnt_chars": 500})

    assert f"файл: {source}" in result
    assert "к-во строк: 2" in result
    assert "файл полностью прочитан" in result
    assert result.endswith("first line\nsecond line\n")


def test_read_file_limits_output_and_reports_truncation(tmp_path):
    source = tmp_path / "large.py"
    source.write_text("x" * 120 + "END", encoding="utf-8")

    result = read_file.invoke({"path": str(source), "cnt_chars": 1})

    assert "файл обрезан на 100 символах" in result
    assert "END" not in result


def test_read_file_does_not_return_more_than_the_effective_limit(tmp_path):
    source = tmp_path / "large.py"
    source.write_text("x" * 120 + "END", encoding="utf-8")

    result = read_file.invoke({"path": str(source), "cnt_chars": 1})
    content = result.split("\n", 5)[5]

    assert content == "x" * 100
    assert "к-во прочитанных символов: 100\n" in result


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("private.pem", "чтение файла запрещено"),
        ("binary.exe", "файлы данного расширения не подходят для чтения"),
    ],
)
def test_read_file_rejects_disallowed_files(tmp_path, name, message):
    source = tmp_path / name
    source.write_text("sample", encoding="utf-8")

    result = read_file.invoke({"path": str(source), "cnt_chars": 500})

    assert message in result


@pytest.mark.parametrize("directory", [".git", ".ssh", ".aws"])
@pytest.mark.parametrize("reader", [read_file, read_file_around_line], ids=lambda item: item.name)
def test_read_file_rejects_forbidden_directories(tmp_path, directory, reader):
    source = tmp_path / directory / "example.py"
    source.parent.mkdir()
    source.write_text("test data", encoding="utf-8")

    arguments = {"path": str(source), "cnt_chars": 500}
    if reader is read_file_around_line:
        arguments["line"] = 1
    result = reader.invoke(arguments)

    assert "чтение файла запрещено" in result


def test_read_file_reports_missing_path(tmp_path):
    result = read_file.invoke(
        {"path": str(tmp_path / "missing.py"), "cnt_chars": 500}
    )

    assert "файл не найден" in result


def test_read_file_rejects_directory_path(tmp_path):
    result = read_file.invoke({"path": str(tmp_path), "cnt_chars": 500})

    assert "это не файл" in result


def test_read_file_around_line_returns_local_context(tmp_path):
    source = tmp_path / "example.py"
    source.write_text(
        "".join(f"line {number}\n" for number in range(1, 31)),
        encoding="utf-8",
    )

    result = read_file_around_line.invoke(
        {"path": str(source), "line": 15, "cnt_chars": 5}
    )

    assert "были прочитаны строки 10-20" in result
    assert "опорная строка: 15" in result
    assert "line 10\n" in result
    assert "line 20\n" in result
    assert "line 9\n" not in result
    assert "line 21\n" not in result


@pytest.mark.parametrize(
    ("line", "message"),
    [(0, "номер строки должен быть >= 1"), (3, "некорректный номер строки")],
)
def test_read_file_around_line_rejects_invalid_line(tmp_path, line, message):
    source = tmp_path / "example.py"
    source.write_text("one\ntwo\n", encoding="utf-8")

    result = read_file_around_line.invoke(
        {"path": str(source), "line": line, "cnt_chars": 5}
    )

    assert message in result


def test_read_file_around_line_reports_empty_file(tmp_path):
    source = tmp_path / "empty.py"
    source.write_text("", encoding="utf-8")

    result = read_file_around_line.invoke(
        {"path": str(source), "line": 1, "cnt_chars": 5}
    )

    assert result == "файл пуст"


def test_read_file_around_line_caps_large_context(tmp_path):
    source = tmp_path / "example.py"
    source.write_text(
        "".join(f"line {number}\n" for number in range(1, 1301)),
        encoding="utf-8",
    )

    result = read_file_around_line.invoke(
        {"path": str(source), "line": 650, "cnt_chars": 800}
    )

    assert "были прочитаны строки 150-1150" in result


def test_semgrep_reports_missing_source_without_running_scan(tmp_path):
    def unexpected_run(*args, **kwargs):
        pytest.fail("Semgrep must not run when the source path is missing")

    with patch.object(subprocess, "run", side_effect=unexpected_run):
        result = run_semgrep.invoke(
            {
                "source_path": str(tmp_path / "missing"),
                "rules_path": str(tmp_path / "rules.yaml"),
            }
        )

    assert "не найден путь" in result


def test_semgrep_reports_scan_failure_for_missing_rules(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    missing_rules = tmp_path / "missing.yaml"

    with patch.object(
        subprocess, "run", return_value=SimpleNamespace(returncode=2, stdout="")
    ) as run:
        result = run_semgrep.invoke(
            {"source_path": str(source), "rules_path": str(missing_rules)}
        )

    run.assert_called_once_with(
        ["semgrep", "scan", "--config", str(missing_rules),
         "--json", "--metrics", "off", str(source)],
        capture_output=True, text=True, timeout=600,
    )
    assert "ошибка" in result
    assert "кодом 2" in result


def test_semgrep_summarizes_findings(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    finding = {
        "check_id": "example-rule",
        "path": "source/app.py",
        "start": {"line": 7},
        "extra": {"severity": "WARNING", "message": "Review query", "lines": "query()"},
    }

    def fake_run(command, **kwargs):
        assert command == [
            "semgrep", "scan", "--config", str(rules),
            "--json", "--metrics", "off", str(source),
        ]
        assert kwargs == {"capture_output": True, "text": True, "timeout": 600}
        return SimpleNamespace(returncode=1, stdout=json.dumps({"results": [finding]}))

    with patch.object(subprocess, "run", side_effect=fake_run):
        result = json.loads(
            run_semgrep.invoke({"source_path": str(source), "rules_path": str(rules)})
        )

    assert result["total_findings"] == 1
    assert result["returned"] == 1
    assert result["findings"] == [
        {
            "check_id": "example-rule",
            "path": "source/app.py",
            "line": 7,
            "severity": "WARNING",
            "message": "Review query",
            "snippet": "query()",
        }
    ]


def test_semgrep_limits_report_to_twenty_findings(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    findings = [
        {
            "check_id": f"rule-{number}",
            "start": {"line": number},
            "extra": {"message": "m" * 105, "lines": "s" * 105},
        }
        for number in range(1, 22)
    ]
    with patch.object(
        subprocess, "run", return_value=SimpleNamespace(
            returncode=1, stdout=json.dumps({"results": findings})
        )
    ):
        result = json.loads(
            run_semgrep.invoke({"source_path": str(source), "rules_path": str(rules)})
        )

    assert result["total_findings"] == 21
    assert result["returned"] == 20
    assert len(result["findings"]) == 20
    assert result["findings"][-1]["check_id"] == "rule-20"
    assert result["findings"][0]["message"] == "m" * 100
    assert result["findings"][0]["snippet"] == "s" * 100


def test_semgrep_reports_empty_results(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    with patch.object(
        subprocess, "run", return_value=SimpleNamespace(
            returncode=0, stdout=json.dumps({"results": []})
        )
    ):
        result = run_semgrep.invoke(
            {"source_path": str(source), "rules_path": str(rules)}
        )

    assert "ничего не нашел" in result


def test_semgrep_reports_process_failure(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    with patch.object(
        subprocess, "run", return_value=SimpleNamespace(returncode=2, stdout="")
    ):
        result = run_semgrep.invoke(
            {"source_path": str(source), "rules_path": str(rules)}
        )

    assert "ошибка" in result
    assert "кодом 2" in result


def test_semgrep_reports_missing_executable(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")

    def missing_executable(*args, **kwargs):
        raise FileNotFoundError("semgrep executable not found")

    with patch.object(subprocess, "run", side_effect=missing_executable):
        result = run_semgrep.invoke(
            {"source_path": str(source), "rules_path": str(rules)}
        )

    assert "ошибка" in result
    assert "semgrep executable not found" in result


@pytest.mark.parametrize(
    ("status", "verdict"),
    [(200, "найдена уязвимость IDOR"), (403, "ОК")],
)
def test_check_idor_sends_bearer_request_and_returns_verdict(status, verdict):
    def fake_get(url, **kwargs):
        assert url == "http://localhost:3000/rest/basket/1"
        assert kwargs == {
            "headers": {"Authorization": "Bearer sample-token"},
            "timeout": 5,
        }
        return SimpleNamespace(status_code=status)

    with patch.object(requests, "get", side_effect=fake_get):
        result = check_idor.invoke(
            {
                "url": "http://localhost:3000",
                "endpoint": "/rest/basket",
                "id_object": "1",
                "token": "sample-token",
            }
        )

    assert result == verdict


def test_check_idor_reports_connection_error():
    def fake_get(*args, **kwargs):
        raise requests.exceptions.ConnectionError("connection refused")

    with patch.object(requests, "get", side_effect=fake_get):
        result = check_idor.invoke(
            {"url": "http://localhost", "endpoint": "/item", "id_object": "1", "token": "x"}
        )

    assert "ошибка запроса" in result
    assert "connection refused" in result


def test_check_idor_reports_timeout():
    def fake_get(*args, **kwargs):
        raise requests.exceptions.Timeout("request timed out")

    with patch.object(requests, "get", side_effect=fake_get):
        result = check_idor.invoke(
            {"url": "http://localhost", "endpoint": "/item", "id_object": "1", "token": "x"}
        )

    assert "ошибка запроса" in result
    assert "request timed out" in result


def test_sqli_login_posts_payload_and_reports_neutral_response():
    def fake_post(url, **kwargs):
        assert url == "http://localhost:3000/rest/user/login"
        assert kwargs == {
            "json": {"email": "' OR 1=1--", "password": "1234567890"},
            "headers": {"Content-Type": "application/json"},
            "timeout": 10,
            "allow_redirects": False,
        }
        return SimpleNamespace(status_code=401, text="Invalid credentials")

    with patch.object(requests, "post", side_effect=fake_post):
        result = json.loads(sqli_login_tool.invoke({"base_url": "http://localhost:3000"}))

    assert result["verdict"] == "ОК"
    assert result["status"] == 401
    assert result["body"] == "invalid credentials"


def test_sqli_login_uses_custom_endpoint_and_payload():
    def fake_post(url, **kwargs):
        assert url == "http://localhost:3000/custom/login"
        assert kwargs["json"] == {"email": "custom@example.test", "password": "custom"}
        return SimpleNamespace(status_code=401, text="Invalid credentials")

    with patch.object(requests, "post", side_effect=fake_post):
        result = json.loads(
            sqli_login_tool.invoke(
                {
                    "base_url": "http://localhost:3000",
                    "endpoint": "/custom/login",
                    "email_payload": "custom@example.test",
                    "password_payload": "custom",
                }
            )
        )

    assert result["url"] == "http://localhost:3000/custom/login"
    assert result["payload"] == {
        "email": "custom@example.test",
        "password": "custom",
    }
    assert result["verdict"] == "ОК"


@pytest.mark.parametrize(
    ("status", "body", "expected_sign"),
    [
        (200, '{"token":"sample"}', "получен токен аутентификации"),
        (200, '{"authentication":"sample"}', "получен токен аутентификации"),
        (500, "SQL syntax error", "внутренняя ошибка"),
        (400, "SQL SYNTAX error", "SQL-ошибки: sql syntax"),
    ],
)
def test_sqli_login_reports_suspicious_response(status, body, expected_sign):
    with patch.object(
        requests, "post", return_value=SimpleNamespace(status_code=status, text=body)
    ):
        result = json.loads(sqli_login_tool.invoke({"base_url": "http://localhost:3000"}))

    assert result["verdict"] == "уязвимо"
    assert result["status"] == status
    assert expected_sign in result["sign"]


def test_sqli_login_reports_timeout():
    def fake_post(*args, **kwargs):
        raise requests.exceptions.Timeout()

    with patch.object(requests, "post", side_effect=fake_post):
        result = sqli_login_tool.invoke({"base_url": "http://localhost:3000"})

    assert result == "таймаут при запросе"


def test_sqli_login_reports_connection_error():
    def fake_post(*args, **kwargs):
        raise requests.exceptions.ConnectionError("connection refused")

    with patch.object(requests, "post", side_effect=fake_post):
        result = sqli_login_tool.invoke({"base_url": "http://localhost:3000"})

    assert result == "не удалось подключиться к http://localhost:3000/rest/user/login"


def test_nuclei_uses_default_command_and_parses_json_lines():
    output = '\n'.join([
        '{"template-id":"first","info":{"severity":"high"}}',
        'not json',
        '',
        '{"template-id":"second"}',
    ])
    with patch.object(
        subprocess, "run",
        return_value=SimpleNamespace(returncode=0, stdout=output, stderr=""),
    ) as run:
        result = json.loads(run_nuclei.invoke({"target_url": "http://example.test"}))

    run.assert_called_once_with(
        ["nuclei", "-u", "http://example.test", "-jsonl", "-silent"],
        capture_output=True, text=True, timeout=300,
    )
    assert result == [
        {"template-id": "first", "info": {"severity": "high"}},
        {"template-id": "second"},
    ]


def test_nuclei_passes_templates_and_severity():
    with patch.object(
        subprocess, "run",
        return_value=SimpleNamespace(returncode=1, stdout='{"id":"finding"}', stderr=""),
    ) as run:
        result = json.loads(run_nuclei.invoke({
            "target_url": "http://example.test",
            "templates": "custom-templates",
            "severity": "high,critical",
        }))

    run.assert_called_once_with(
        ["nuclei", "-u", "http://example.test", "-jsonl", "-silent",
         "-t", "custom-templates", "-severity", "high,critical"],
        capture_output=True, text=True, timeout=300,
    )
    assert result == [{"id": "finding"}]


@pytest.mark.parametrize("stdout", ["", "invalid json\n  "])
def test_nuclei_reports_no_findings(stdout):
    with patch.object(
        subprocess, "run",
        return_value=SimpleNamespace(returncode=0, stdout=stdout, stderr=""),
    ):
        result = run_nuclei.invoke({"target_url": "http://example.test"})

    assert result == "находок не обнаружено"


def test_nuclei_reports_process_failure():
    with patch.object(
        subprocess, "run",
        return_value=SimpleNamespace(returncode=2, stdout="", stderr="invalid option\n"),
    ):
        result = run_nuclei.invoke({"target_url": "http://example.test"})

    assert result == "ошибка запуска nuclei: invalid option"


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (subprocess.TimeoutExpired("nuclei", 300), "Error: таймаут выполнения nuclei"),
        (FileNotFoundError("nuclei"), "Error: nuclei не установлен или не найден в PATH"),
        (OSError("cannot start"), "ошибка запроса cannot start"),
    ],
)
def test_nuclei_reports_execution_errors(error, message):
    with patch.object(subprocess, "run", side_effect=error):
        result = run_nuclei.invoke({"target_url": "http://example.test"})

    assert result == message


@pytest.fixture
def zap_report_dir(tmp_path):
    report_dir = tmp_path / "reports"
    fake_path = SimpleNamespace(
        abspath=lambda path: str(report_dir),
        join=os.path.join,
        exists=os.path.exists,
    )
    fake_os = SimpleNamespace(path=fake_path, makedirs=os.makedirs)
    with patch.object(zap_module, "os", fake_os):
        yield report_dir


def test_zap_rejects_unknown_mode_before_running_docker():
    with patch.object(subprocess, "run") as run:
        result = run_zap_scan.invoke({
            "target_url": "http://example.test", "scan_mode": "unknown",
        })

    assert result == "нет режима unknown"
    run.assert_not_called()


@pytest.mark.parametrize(
    ("mode", "script"),
    [
        ("baseline", "zap-baseline.py"),
        (" FULL ", "zap-full-scan.py"),
        ("api", "zap-api-scan.py"),
    ],
)
def test_zap_uses_selected_mode_and_summarizes_alerts(zap_report_dir, mode, script):
    target = "http://example.test"
    report = {"site": [{"alerts": [{
        "alert": "SQL Injection", "riskdesc": "High", "confidence": "Medium",
        "desc": "d" * 205, "solution": "s" * 205,
        "instances": [
            {"uri": target + "/login", "method": "POST", "param": "email", "evidence": "e" * 205},
            {"uri": target + "/other"},
        ],
    }]}]}

    def fake_run(command, **kwargs):
        if command == ["docker", "info"]:
            assert kwargs == {"capture_output": True, "text": True, "timeout": 5}
            return SimpleNamespace(returncode=0)
        assert command == [
            "docker", "run", "--rm", "--user", "root", "--network", "host",
            "-v", f"{zap_report_dir}:/zap/wrk/:rw", "zaproxy/zap-stable",
            script, "-t", target, "-J", "zap_report.json",
            "-r", "zap_report.html", "-I",
        ]
        assert kwargs == {"capture_output": True, "text": True, "timeout": 1800}
        (zap_report_dir / "zap_report.json").write_text(json.dumps(report), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch.object(subprocess, "run", side_effect=fake_run) as run:
        result = json.loads(run_zap_scan.invoke({"target_url": target, "scan_mode": mode}))

    assert run.call_count == 2
    assert result == {
        "scan_mode": mode.lower().strip(),
        "target_url": target,
        "total_alerts": 1,
        "alerts": [{
            "alert": "SQL Injection", "risk": "High", "confidence": "Medium",
            "url": target + "/login", "method": "POST", "param": "email",
            "evidence": "e" * 200, "description": "d" * 200,
            "solution": "s" * 200, "instances_count": 2,
        }],
        "reports": {
            "json": str(zap_report_dir / "zap_report.json"),
            "html": str(zap_report_dir / "zap_report.html"),
        },
    }


def test_zap_reports_docker_not_running(zap_report_dir):
    with patch.object(
        subprocess, "run", return_value=SimpleNamespace(returncode=1)
    ) as run:
        result = run_zap_scan.invoke({
            "target_url": "http://example.test", "scan_mode": "baseline",
        })

    assert result == "Docker не запущен"
    run.assert_called_once_with(
        ["docker", "info"], capture_output=True, text=True, timeout=5,
    )


def test_zap_reports_docker_check_exception(zap_report_dir):
    with patch.object(subprocess, "run", side_effect=FileNotFoundError("docker")):
        result = run_zap_scan.invoke({
            "target_url": "http://example.test", "scan_mode": "baseline",
        })

    assert result == "ошибка проверки Docker docker"


def test_zap_reports_scan_exception(zap_report_dir):
    with patch.object(subprocess, "run", side_effect=[
        SimpleNamespace(returncode=0), subprocess.TimeoutExpired("docker", 1800),
    ]):
        result = run_zap_scan.invoke({
            "target_url": "http://example.test", "scan_mode": "baseline",
        })

    assert "возникла ошибка:" in result
    assert "timed out" in result


def test_zap_reports_missing_report(zap_report_dir):
    with patch.object(subprocess, "run", side_effect=[
        SimpleNamespace(returncode=0),
        SimpleNamespace(returncode=0, stdout="", stderr=""),
    ]):
        result = run_zap_scan.invoke({
            "target_url": "http://example.test", "scan_mode": "baseline",
        })

    assert result == f"ZAP: отчёт не создан: {zap_report_dir / 'zap_report.json'}"


@pytest.mark.parametrize(
    ("report_text", "message"),
    [("not json", "при чтении json возникла ошибка"),
     ('{"site": []}', "алертов не найдено")],
)
def test_zap_handles_invalid_or_empty_report(zap_report_dir, report_text, message):
    def fake_run(command, **kwargs):
        if command == ["docker", "info"]:
            return SimpleNamespace(returncode=0)
        (zap_report_dir / "zap_report.json").write_text(report_text, encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch.object(subprocess, "run", side_effect=fake_run):
        result = run_zap_scan.invoke({
            "target_url": "http://example.test", "scan_mode": "baseline",
        })

    assert message in result


def test_zap_limits_returned_alerts_to_thirty(zap_report_dir):
    report = {"site": [{"alerts": [
        {"alert": f"alert-{number}"} for number in range(31)
    ]}]}

    def fake_run(command, **kwargs):
        if command == ["docker", "info"]:
            return SimpleNamespace(returncode=0)
        (zap_report_dir / "zap_report.json").write_text(json.dumps(report), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch.object(subprocess, "run", side_effect=fake_run):
        result = json.loads(run_zap_scan.invoke({
            "target_url": "http://example.test", "scan_mode": "baseline",
        }))

    assert result["total_alerts"] == 31
    assert len(result["alerts"]) == 30
    assert result["alerts"][-1]["alert"] == "alert-29"
    assert result["alerts"][0]["instances_count"] == 0


def test_list_files_returns_sorted_files_and_total(tmp_path):
    (tmp_path / "z_last.py").write_text("last", encoding="utf-8")
    (tmp_path / "a_first.py").write_text("first", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "child.py").write_text("child", encoding="utf-8")

    result = list_files.invoke({"path": str(tmp_path)})

    assert result.startswith(f"Каталог {tmp_path} — 3 файлов:\n")
    assert f"{tmp_path.name}/" in result
    assert "nested/" in result
    assert "child.py" in result
    assert result.index("a_first.py") < result.index("z_last.py")


@pytest.mark.parametrize(
    "directory", [".git", "__pycache__", ".venv", "venv", "node_modules"]
)
def test_list_files_ignores_generated_and_dependency_directories(tmp_path, directory):
    ignored = tmp_path / directory / "nested"
    ignored.mkdir(parents=True)
    (ignored / "hidden_file.py").write_text("hidden", encoding="utf-8")
    (tmp_path / "visible.py").write_text("visible", encoding="utf-8")

    result = list_files.invoke({"path": str(tmp_path)})

    assert result.startswith(f"Каталог {tmp_path} — 1 файлов:\n")
    assert "visible.py" in result
    assert f"{directory}/" not in result
    assert "hidden_file.py" not in result


def test_list_files_reports_missing_path(tmp_path):
    missing = tmp_path / "missing"

    result = list_files.invoke({"path": str(missing)})

    assert result == f"не найден путь: {missing}"


def test_list_files_rejects_file_path(tmp_path):
    source = tmp_path / "example.py"
    source.write_text("sample", encoding="utf-8")

    result = list_files.invoke({"path": str(source)})

    assert result == f"это не каталог: {source}"


def test_list_files_reports_empty_directory(tmp_path):
    result = list_files.invoke({"path": str(tmp_path)})

    assert result == f"в {tmp_path} нет файлов"


@pytest.mark.parametrize("max_depth", [0, 1, 2])
def test_list_files_respects_max_depth(tmp_path, max_depth):
    (tmp_path / "root.py").write_text("root", encoding="utf-8")
    child = tmp_path / "child"
    child.mkdir()
    (child / "included.py").write_text("included", encoding="utf-8")
    grandchild = child / "grandchild"
    grandchild.mkdir()
    (grandchild / "excluded.py").write_text("excluded", encoding="utf-8")

    result = list_files.invoke({"path": str(tmp_path), "max_depth": max_depth})

    assert result.startswith(f"Каталог {tmp_path} — {max_depth + 1} файлов:\n")
    for depth, filename in enumerate(("root.py", "included.py", "excluded.py")):
        assert (filename in result) == (depth <= max_depth)
    assert ("grandchild/" in result) == (max_depth == 2)


def test_sqli_lab_get_uses_default_parameter_and_reports_neutral_response():
    with patch.object(
        sqli_lab_module.requests, "get",
        return_value=SimpleNamespace(status_code=200, text="No matching user"),
    ) as get, patch.object(sqli_lab_module.requests, "post") as post:
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/check_user",
            "payload": "1 OR 1=1",
        })

    get.assert_called_once_with(
        "http://example.test/api/check_user", params={"q": "1 OR 1=1"}, timeout=30,
    )
    post.assert_not_called()
    assert result == (
        "URL: http://example.test/api/check_user\n"
        "payload: 1 OR 1=1\n"
        "status: 200\n"
        "вердикт: ОК\n"
        "indicators: []\n"
        "body: No matching user"
    )


def test_sqli_lab_post_uses_custom_parameter_and_accepts_lowercase_method():
    payload = "admin' --"
    with patch.object(
        sqli_lab_module.requests, "post",
        return_value=SimpleNamespace(status_code=401, text="Invalid credentials"),
    ) as post, patch.object(sqli_lab_module.requests, "get") as get:
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/login",
            "payload": payload, "param": "username", "method": "post",
        })

    post.assert_called_once_with(
        "http://example.test/api/login", json={"username": payload}, timeout=30,
    )
    get.assert_not_called()
    assert "status: 401\n" in result
    assert "вердикт: ОК\n" in result


@pytest.mark.parametrize(
    ("status", "body", "indicator"),
    [
        (200, '{"status": "OK"}', "auth bypass status OK"),
        (500, "SQL Syntax ERROR", "SQL-ошибка в ответе"),
        (200, "FLAG{test-secret-value}", "утечка секрета (FLAG)"),
        (200, "SECRET value exposed", "утечка secrets"),
    ],
)
def test_sqli_lab_reports_sqli_indicators(status, body, indicator):
    with patch.object(
        sqli_lab_module.requests, "get",
        return_value=SimpleNamespace(status_code=status, text=body),
    ):
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/check_user",
            "payload": "1'", "param": "id",
        })

    assert "вердикт: SQLi ПОДТВЕРЖДЁН\n" in result
    assert indicator in result.split("indicators: ", 1)[1].split("\n", 1)[0]
    assert f"status: {status}\n" in result
    assert result.endswith(f"body: {body}")


def test_sqli_lab_collects_all_indicators():
    body = '{"status": "OK", "error": "SQL", "secret": "FLAG{sample}"}'
    with patch.object(
        sqli_lab_module.requests, "get",
        return_value=SimpleNamespace(status_code=200, text=body),
    ):
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/login",
            "payload": "1'",
        })

    assert (
        "indicators: ['auth bypass status OK', 'SQL-ошибка в ответе', "
        "'утечка секрета (FLAG)', 'утечка secrets']\n"
    ) in result


@pytest.mark.parametrize(
    ("status", "body"),
    [(401, '{"status": "OK"}'), (200, "SQL query completed"), (500, "Internal error")],
)
def test_sqli_lab_does_not_flag_responses_without_matching_indicators(status, body):
    with patch.object(
        sqli_lab_module.requests, "get",
        return_value=SimpleNamespace(status_code=status, text=body),
    ):
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/check_user",
            "payload": "1",
        })

    assert "вердикт: ОК\n" in result
    assert "indicators: []\n" in result


@pytest.mark.parametrize("body", [None, ""])
def test_sqli_lab_handles_empty_response_body(body):
    with patch.object(
        sqli_lab_module.requests, "get",
        return_value=SimpleNamespace(status_code=204, text=body),
    ):
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/check_user",
            "payload": "1",
        })

    assert result.endswith("body: ")
    assert "вердикт: ОК\n" in result


def test_sqli_lab_limits_response_body_to_fifteen_hundred_characters():
    body = "x" * 1500 + "END"
    with patch.object(
        sqli_lab_module.requests, "get",
        return_value=SimpleNamespace(status_code=200, text=body),
    ):
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/check_user",
            "payload": "1",
        })

    assert result.split("body: ", 1)[1] == "x" * 1500


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize(
    "error",
    [requests.exceptions.Timeout("request timed out"),
     requests.exceptions.ConnectionError("connection refused")],
)
def test_sqli_lab_reports_request_errors(method, error):
    request_name = method.lower()
    with patch.object(sqli_lab_module.requests, request_name, side_effect=error):
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/check_user",
            "payload": "1'", "method": method,
        })

    assert result == f"ошибка: {error}"


# LFI / RFI: local fixtures, real HTTP checks, and false-positive controls.

FILE_INCLUSION_ROOT = Path(__file__).resolve().parents[1]


class FileInclusionQuietHandler(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass


@contextmanager
def _serve_file_inclusion(app):
    server = make_server("127.0.0.1", 0, app, threaded=True,
                         request_handler=FileInclusionQuietHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@pytest.fixture(scope="module")
def file_inclusion_servers():
    with _serve_file_inclusion(file_inclusion_remote_app) as remote, _serve_file_inclusion(file_inclusion_app) as target:
        yield target, remote + "/payload.py"


def test_file_inclusion_local_baseline_and_path_traversal_execute_different_modules():
    with file_inclusion_app.test_client() as client:
        baseline = client.get("/api/lfi", query_string={"file": "welcome.py"})
        exploit = client.get("/api/lfi", query_string={"file": "../fi_private_page.py"})
    assert baseline.status_code == exploit.status_code == 200
    assert baseline.json["content"] == "WELCOME_FILE_INCLUSION_LAB"
    assert exploit.json["content"] == "LFI_PRIVATE_FIXTURE:42"
    # Reading source alone would not produce the computed inclusion result.
    source = (FILE_INCLUSION_PUBLIC_DIR.parent / "fi_private_page.py").read_text(encoding="utf-8")
    assert exploit.json["content"] not in source


@pytest.mark.parametrize("filename", [
    "../fi_private_page.py",
    str((FILE_INCLUSION_PUBLIC_DIR.parent / "fi_private_page.py").resolve()),
    "../../app.py",
])
def test_file_inclusion_fixed_lfi_rejects_traversal_and_absolute_paths(filename):
    with file_inclusion_app.test_client() as client:
        response = client.get("/api/lfi-safe", query_string={"file": filename})
        baseline = client.get("/api/lfi-safe", query_string={"file": "welcome.py"})
    assert response.status_code == 403
    assert "content" not in response.json
    assert baseline.status_code == 200
    assert baseline.json["content"] == "WELCOME_FILE_INCLUSION_LAB"


def test_file_inclusion_missing_file_and_missing_remote_url_are_not_successes():
    with file_inclusion_app.test_client() as client:
        assert client.get("/api/lfi?file=missing.py").status_code == 404
        assert client.get("/api/rfi").status_code == 400


def test_file_inclusion_remote_fixture_is_executed_rather_than_only_downloaded(file_inclusion_servers):
    target, remote = file_inclusion_servers
    payload_url = remote + "?nonce=execution-proof"
    source = requests.get(payload_url, timeout=5).text
    expected = "RFI_EXECUTED:execution-proof:42"
    assert expected not in source
    response = requests.get(target + "/api/rfi", params={"url": payload_url}, timeout=10)
    assert response.status_code == 200
    assert response.json()["content"] == expected


def test_file_inclusion_remote_nonce_cannot_inject_code_into_fixture(file_inclusion_servers):
    _, remote = file_inclusion_servers
    nonce = "'; raise RuntimeError('injected'); #"
    source = requests.get(remote, params={"nonce": nonce}, timeout=5).text
    namespace = {}
    exec(source, namespace)
    assert namespace["CONTENT"] == f"RFI_EXECUTED:{nonce}:42"


def test_file_inclusion_fixed_rfi_does_not_even_fetch_remote_code():
    with patch("target.LFI_RFI_service.requests.get") as get:
        with file_inclusion_app.test_client() as client:
            response = client.get("/api/rfi-safe", query_string={
                "url": "http://127.0.0.1:5102/payload.py",
            })
    assert response.status_code == 403
    get.assert_not_called()


def test_file_inclusion_scanner_confirms_both_vulnerabilities_with_separate_evidence(file_inclusion_servers):
    target, remote = file_inclusion_servers
    report = scan_file_inclusion_lab(target, remote + "?nonce=old&keep=value")
    lfi, rfi = report["checks"]
    assert (lfi["type"], lfi["status"]) == ("LFI", "confirmed")
    assert (rfi["type"], rfi["status"]) == ("RFI", "confirmed")
    evidence = rfi["evidence"]
    response = evidence["payload_response"]
    assert response["content"] == evidence["expected_execution_result"]
    assert response["content"] not in response["params"]["url"]
    assert "keep=value" in response["params"]["url"]
    assert "nonce=old" not in response["params"]["url"]


def test_file_inclusion_scanner_does_not_confirm_fixed_controls(file_inclusion_servers):
    target, remote = file_inclusion_servers
    report = scan_file_inclusion_lab(target, remote, "/api/lfi-safe", "/api/rfi-safe")
    for check in report["checks"]:
        assert check["status"] == "requires_verification"
        assert check["evidence"]["payload_response"]["status_code"] == 403


@pytest.mark.parametrize("body,status", [
    ({"content": "LFI RFI error /etc/passwd"}, 200),
    ({"content": "LFI_PRIVATE_FIXTURE:42"}, 500),
    (["LFI_PRIVATE_FIXTURE:42"], 200),
    ("downloaded remote source", 200),
])
def test_file_inclusion_generic_bodies_and_error_codes_are_not_proof(body, status):
    response = requests.Response()
    response.status_code = status
    response.url = "http://lab.test/api/lfi"
    response._content = json.dumps(body).encode()
    with patch("tools.file_inclusion_probe.requests.get", return_value=response):
        report = scan_file_inclusion_lab("http://lab.test", "http://fixture.test/payload.py")
    assert all(item["status"] == "requires_verification" for item in report["checks"])


def test_file_inclusion_network_failures_preserve_both_checks_without_claiming_security():
    with patch("tools.file_inclusion_probe.requests.get",
               side_effect=requests.Timeout("timeout")):
        report = scan_file_inclusion_lab("http://lab.test", "http://fixture.test/payload.py")
    for check in report["checks"]:
        assert check["status"] == "requires_verification"
        assert check["evidence"]["payload_response"]["error"] == "timeout"


@pytest.mark.parametrize("endpoint", ["https://other.test", "//other.test", "api/lfi"])
def test_file_inclusion_scanner_rejects_nonlocal_endpoint_paths(endpoint):
    with pytest.raises(ValueError, match="Endpoints"):
        scan_file_inclusion_lab("http://lab.test", "http://fixture.test/payload.py", endpoint)


def test_file_inclusion_cli_saves_a_real_report_without_an_llm(file_inclusion_servers, tmp_path):
    target, remote = file_inclusion_servers
    output = tmp_path / "scan.json"
    result = subprocess.run([
        sys.executable, str(FILE_INCLUSION_ROOT / "tools" / "file_inclusion_probe.py"), "--url", target,
        "--remote-url", remote, "--output", str(output),
    ], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved == json.loads(result.stdout)
    assert all(check["status"] == "confirmed" for check in saved["checks"])


def test_file_inclusion_registered_tool_returns_evidence_without_changing_registry(file_inclusion_servers):
    import tools
    original_names = [item.name for item in tools.ALL_TOOLS]
    from tools import check_file_inclusion

    target, remote = file_inclusion_servers
    report = json.loads(check_file_inclusion.invoke({
        "base_url": target, "remote_payload_url": remote,
    }))
    assert all(check["status"] == "confirmed" for check in report["checks"])
    assert [item.name for item in tools.ALL_TOOLS] == original_names


def test_file_inclusion_launcher_passes_a_scoped_task_to_the_existing_agent():
    arguments = [
        "run_file_inclusion_agent.py", "--url", "http://lab.test",
        "--remote-url", "http://fixture.test/payload.py",
    ]
    previous_directory = Path.cwd()
    try:
        os.chdir(FILE_INCLUSION_ROOT)
        with (
            patch.object(sys, "argv", arguments),
            patch.object(sys, "path", list(sys.path)),
            patch.object(file_inclusion_agent_launcher.runpy, "run_path") as launch,
        ):
            file_inclusion_agent_launcher.main()
            forwarded_args = list(sys.argv)
    finally:
        os.chdir(previous_directory)
    launch.assert_called_once_with(str(FILE_INCLUSION_ROOT / "agent.py"), run_name="__main__")
    assert forwarded_args[:2] == [str(FILE_INCLUSION_ROOT / "agent.py"), "--task"]
    assert "http://lab.test" in forwarded_args[2]
    assert "http://fixture.test/payload.py" in forwarded_args[2]
    assert repr(str((FILE_INCLUSION_ROOT / "rules" / "rules_semgrep.yaml").resolve())) in forwarded_args[2]
    assert repr(str((FILE_INCLUSION_ROOT / "target" / "LFI_RFI_service.py").resolve())) in forwarded_args[2]
    assert "/api/lfi-safe" in forwarded_args[2] and "/api/rfi-safe" in forwarded_args[2]


def test_file_inclusion_tool_passes_custom_endpoints(file_inclusion_servers):
    target, remote = file_inclusion_servers

    report = json.loads(check_file_inclusion.invoke({
        "base_url": target, "remote_payload_url": remote,
        "lfi_endpoint": "/api/lfi-safe", "rfi_endpoint": "/api/rfi-safe",
    }))

    assert [item["location"] for item in report["checks"]] == [
        "/api/lfi-safe", "/api/rfi-safe",
    ]
    assert all(item["status"] == "requires_verification" for item in report["checks"])
    assert all(
        item["evidence"]["payload_response"]["status_code"] == 403
        for item in report["checks"]
    )


@pytest.mark.parametrize("invalid_arguments", [
    {"base_url": "file:///tmp/lab"},
    {"remote_payload_url": "not-a-url"},
    {"lfi_endpoint": "//other.test/lfi"},
    {"rfi_endpoint": "https://other.test/rfi"},
])
def test_file_inclusion_tool_returns_validation_errors_without_http(invalid_arguments):
    arguments = {
        "base_url": "http://lab.test",
        "remote_payload_url": "http://fixture.test/payload.py",
        **invalid_arguments,
    }
    with patch.object(requests, "get") as get:
        result = json.loads(check_file_inclusion.invoke(arguments))

    assert set(result) == {"error"}
    assert result["error"]
    get.assert_not_called()


@pytest.mark.parametrize("endpoint", [None, "/custom/login"])
def test_nosqli_lab_posts_operator_payload(endpoint):
    arguments = {"url": "http://lab.test"}
    if endpoint is not None:
        arguments["endpoint"] = endpoint
    with patch.object(
        requests, "post",
        return_value=SimpleNamespace(status_code=401, text="Invalid credentials"),
    ) as post:
        result = nosqli_lab_tool.invoke(arguments)

    post.assert_called_once_with(
        "http://lab.test" + (endpoint or "/api/login"),
        json={"username": {"$ne": None}, "password": {"$ne": None}},
        timeout=10,
    )
    assert result == "status=401 body=Invalid credentials verdict=ОК"


@pytest.mark.parametrize("status,body,verdict", [
    (200, '{"username":"admin","role":"admin"}', "найдена уязвимость NoSQLi"),
    (200, '{"username":"admin"}', "ОК"),
    (200, '{"role":"admin"}', "ОК"),
    (200, "username role", "ОК"),
    (200, "", "ОК"),
    (401, '{"username":"admin","role":"admin"}', "ОК"),
    (500, '{"username":"admin","role":"admin"}', "ОК"),
])
def test_nosqli_lab_requires_success_and_both_response_fields(status, body, verdict):
    with patch.object(
        requests, "post", return_value=SimpleNamespace(status_code=status, text=body),
    ):
        result = nosqli_lab_tool.invoke({"url": "http://lab.test"})

    assert result == f"status={status} body={body} verdict={verdict}"


def test_nosqli_lab_truncates_body_but_checks_full_response():
    body = "x" * 300 + '{"username":"admin","role":"admin"}'
    with patch.object(
        requests, "post", return_value=SimpleNamespace(status_code=200, text=body),
    ):
        result = nosqli_lab_tool.invoke({"url": "http://lab.test"})

    assert result == f"status=200 body={'x' * 300} verdict=найдена уязвимость NoSQLi"


@pytest.mark.parametrize("error", [
    requests.Timeout("request timed out"),
    requests.ConnectionError("connection refused"),
])
def test_nosqli_lab_reports_request_errors(error):
    with patch.object(requests, "post", side_effect=error):
        result = nosqli_lab_tool.invoke({"url": "http://lab.test"})

    assert result == f"ошибка запроса {error}"


@pytest.fixture
def arp_container():
    # Each test creates snapshots through the public tool, then removes its state.
    name = "pytest-arp-" + uuid4().hex
    try:
        yield name
    finally:
        arp_table_module.SNAPSHOTS.pop(name, None)


def test_arp_table_parses_neighbor_states_and_saves_baseline(arp_container):
    states = ["REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "INCOMPLETE", "PERMANENT"]
    expected = [
        {"ip": f"192.0.2.{index}", "mac": f"02:00:00:00:00:{index:02x}", "state": state}
        for index, state in enumerate(states, start=1)
    ]
    expected.append({"ip": "2001:db8::1", "mac": "02:00:00:00:00:08", "state": "UNKNOWN"})
    output = "\n".join(
        f"{entry['ip']} dev eth0 lladdr {entry['mac']} {entry['state']}"
        for entry in expected
    )
    with patch.object(
        subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=output),
    ) as run:
        result = json.loads(check_arp_table.invoke({"container_name": arp_container}))

    run.assert_called_once_with(
        ["docker", "exec", arp_container, "ip", "neigh", "show"],
        capture_output=True, text=True, timeout=10,
    )
    assert result["container"] == arp_container
    assert result["total_entries"] == len(expected)
    assert result["entries"] == expected
    assert result["anomalies"] == []
    assert result["verdict"] == "закрелено начальное состояние таблицы"


@pytest.mark.parametrize("output", [
    "", "  \n ",
    "short line\n192.0.2.1 dev eth0 FAILED\n192.0.2.2 dev eth0 lladdr",
])
def test_arp_table_ignores_entries_without_mac(arp_container, output):
    with patch.object(
        subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=output),
    ):
        result = json.loads(check_arp_table.invoke({"container_name": arp_container}))

    assert result["total_entries"] == 0
    assert result["entries"] == result["anomalies"] == []


def test_arp_table_detects_mac_change_and_updates_previous_snapshot(arp_container):
    original = "192.0.2.1 dev eth0 lladdr 02:00:00:00:00:01 REACHABLE"
    changed = "192.0.2.1 dev eth0 lladdr 02:00:00:00:00:02 STALE"
    with patch.object(subprocess, "run", side_effect=[
        SimpleNamespace(returncode=0, stdout=output)
        for output in (original, changed, changed)
    ]):
        check_arp_table.invoke({"container_name": arp_container})
        result = json.loads(check_arp_table.invoke({
            "container_name": arp_container, "compare_with_previous": True,
        }))
        repeated = json.loads(check_arp_table.invoke({
            "container_name": arp_container, "compare_with_previous": True,
        }))

    assert result["verdict"] == "найдены аномалии"
    assert result["anomalies"] == [{
        "ip": "192.0.2.1", "old_mac": "02:00:00:00:00:01",
        "new_mac": "02:00:00:00:00:02", "severity": "HIGH",
        "reason": "MAC изменился - возможен ARP-спуфинг",
    }]
    assert repeated["anomalies"] == []
    assert repeated["verdict"] == "OK"


def test_arp_table_does_not_compare_when_flag_is_false(arp_container):
    with patch.object(subprocess, "run", side_effect=[
        SimpleNamespace(returncode=0, stdout=f"192.0.2.1 dev eth0 lladdr {mac} REACHABLE")
        for mac in ("02:00:00:00:00:01", "02:00:00:00:00:02")
    ]):
        check_arp_table.invoke({"container_name": arp_container})
        result = json.loads(check_arp_table.invoke({"container_name": arp_container}))

    assert result["anomalies"] == []
    assert result["verdict"] == "закрелено начальное состояние таблицы"


def test_arp_table_keeps_container_snapshots_separate(arp_container):
    other = arp_container + "-other"
    try:
        with patch.object(subprocess, "run", side_effect=[
            SimpleNamespace(returncode=0, stdout=f"192.0.2.1 dev eth0 lladdr {mac} REACHABLE")
            for mac in ("02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:01")
        ]):
            check_arp_table.invoke({"container_name": arp_container})
            initial = json.loads(check_arp_table.invoke({
                "container_name": other, "compare_with_previous": True,
            }))
            repeated = json.loads(check_arp_table.invoke({
                "container_name": arp_container, "compare_with_previous": True,
            }))
    finally:
        arp_table_module.SNAPSHOTS.pop(other, None)

    assert initial["anomalies"] == repeated["anomalies"] == []
    assert initial["verdict"] == repeated["verdict"] == "OK"


def test_arp_table_reports_docker_failure_without_overwriting_snapshot(arp_container):
    output = "192.0.2.1 dev eth0 lladdr 02:00:00:00:00:01 REACHABLE"
    stderr = "container unavailable " + "x" * 120
    with patch.object(subprocess, "run", side_effect=[
        SimpleNamespace(returncode=0, stdout=output),
        SimpleNamespace(returncode=1, stderr="  " + stderr + "  "),
        SimpleNamespace(returncode=0, stdout=output),
    ]):
        check_arp_table.invoke({"container_name": arp_container})
        failed = check_arp_table.invoke({"container_name": arp_container})
        repeated = json.loads(check_arp_table.invoke({
            "container_name": arp_container, "compare_with_previous": True,
        }))

    assert failed == f"в {arp_container} возникла ошибка: {stderr[:100]}"
    assert repeated["anomalies"] == []
    assert repeated["verdict"] == "OK"


@pytest.mark.parametrize("error,message", [
    (FileNotFoundError("docker"), "docker не установлен"),
    (subprocess.TimeoutExpired("docker", 10), None),
])
def test_arp_table_reports_execution_errors(arp_container, error, message):
    with patch.object(subprocess, "run", side_effect=error):
        result = check_arp_table.invoke({"container_name": arp_container})

    assert result == (message or f"возникла ошибка: {error}")


@pytest.mark.parametrize("original", [
    "", "192.0.2.1 dev eth0 lladdr 02:00:00:00:00:01 REACHABLE",
])
def test_arp_table_reports_new_neighbor_as_medium_anomaly(arp_container, original):
    added = original + "\n192.0.2.2 dev eth0 lladdr 02:00:00:00:00:02 STALE"
    with patch.object(subprocess, "run", side_effect=[
        SimpleNamespace(returncode=0, stdout=output) for output in (original, added)
    ]):
        check_arp_table.invoke({"container_name": arp_container})
        result = json.loads(check_arp_table.invoke({
            "container_name": arp_container, "compare_with_previous": True,
        }))

    assert result["verdict"] == "найдены аномалии"
    assert len(result["anomalies"]) == 1
    anomaly = result["anomalies"][0]
    assert anomaly["ip"] == "192.0.2.2"
    assert anomaly["old_mac"] is None
    assert anomaly["new_mac"] == "02:00:00:00:00:02"
    assert anomaly["severity"] == "MEDIUM"


@pytest.mark.parametrize("returncode", [0, 124])
def test_arp_spoof_runs_default_lab_command_and_returns_output(returncode):
    with patch.object(
        subprocess, "run",
        return_value=SimpleNamespace(returncode=returncode, stdout="lab output", stderr="lab warning"),
    ) as run:
        result = run_arp_spoof.invoke({})

    run.assert_called_once_with(
        ["docker", "exec", "-e", "VICTIM_IP=172.28.0.10", "-e", "TARGET_IP=172.28.0.20",
         "spoof-attacker", "timeout", "10", "python3", "/app/arp_spoofing.py"],
        capture_output=True, text=True, timeout=20,
    )
    assert "victim: 172.28.0.10\n" in result
    assert "target: 172.28.0.20\n" in result
    assert "attacker: spoof-attacker" in result
    assert "stdout\nlab output\n" in result
    assert result.endswith("stderr\nlab warning")


def test_arp_spoof_uses_custom_attacker_container():
    with patch.object(
        subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="", stderr=""),
    ) as run:
        result = run_arp_spoof.invoke({"attacker": "custom-lab-attacker"})

    assert run.call_args.args[0][6] == "custom-lab-attacker"
    assert "attacker: custom-lab-attacker" in result


@pytest.mark.parametrize("stdout,stderr", [(None, None), ("x" * 1001, "e" * 501)])
def test_arp_spoof_handles_empty_output_and_limits_report(stdout, stderr):
    with patch.object(
        subprocess, "run",
        return_value=SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr),
    ):
        result = run_arp_spoof.invoke({})

    output = result.split("stdout\n", 1)[1]
    assert output == f"{(stdout or '')[:1000]}\nstderr\n{(stderr or '')[:500]}"


@pytest.mark.parametrize("error", [
    FileNotFoundError("docker"), subprocess.TimeoutExpired("docker", 20),
])
def test_arp_spoof_reports_launch_errors(error):
    with patch.object(subprocess, "run", side_effect=error):
        result = run_arp_spoof.invoke({})

    assert result == f"возникла ошибка запуска: {error}"


@pytest.mark.parametrize("returncode", [1, 125, 126, 127, 137])
def test_arp_spoof_does_not_report_success_when_container_fails(returncode):
    with patch.object(
        subprocess, "run",
        return_value=SimpleNamespace(returncode=returncode, stdout="", stderr="container unavailable"),
    ):
        result = run_arp_spoof.invoke({})

    assert "container unavailable" in result
    assert f"код {returncode}" in result
    assert "был запущен ARP-spoofing" not in result


def test_arp_spoof_forwards_custom_ips_to_process():
    with patch.object(
        subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="", stderr=""),
    ) as run:
        run_arp_spoof.invoke({"victim_ip": "192.0.2.10", "target_ip": "192.0.2.20"})

    command = run.call_args.args[0]
    assert command[2:6] == ["-e", "VICTIM_IP=192.0.2.10", "-e", "TARGET_IP=192.0.2.20"]


@pytest.mark.parametrize("custom_ips", [False, True])
def test_arp_lab_script_reads_ip_configuration_without_sending_packets(tmp_path, custom_ips):
    # A local Scapy substitute makes the real script exit before any packet send.
    scapy = tmp_path / "scapy"
    scapy.mkdir()
    (scapy / "__init__.py").write_text("", encoding="utf-8")
    (scapy / "all.py").write_text(
        "class Packet:\n"
        "    def __init__(self, *args, **kwargs): pass\n"
        "    def __truediv__(self, other): return self\n"
        "ARP = Ether = Packet\n"
        "def get_if_hwaddr(*args): return '02:00:00:00:00:01'\n"
        "def srp(*args, **kwargs): return [], []\n"
        "def sendp(*args, **kwargs): raise AssertionError('Unexpected packet send')\n",
        encoding="utf-8",
    )
    environment = dict(os.environ, PYTHONPATH=str(tmp_path))
    for name in ("VICTIM_IP", "TARGET_IP"):
        environment.pop(name, None)
    if custom_ips:
        environment.update(VICTIM_IP="192.0.2.10", TARGET_IP="192.0.2.20")

    result = subprocess.run(
        [sys.executable, "-B", str(FILE_INCLUSION_ROOT / "laboratorys" / "spoofing" / "arp_spoofing.py")],
        capture_output=True, text=True, encoding="utf-8", timeout=10,
        env=dict(environment, PYTHONIOENCODING="utf-8"),
    )

    assert result.returncode == 0, result.stderr
    victim = "192.0.2.10" if custom_ips else "172.28.0.10"
    target = "192.0.2.20" if custom_ips else "172.28.0.20"
    assert f"жертва: {victim} -> None" in result.stdout
    assert f"цель: {target} -> None" in result.stdout
