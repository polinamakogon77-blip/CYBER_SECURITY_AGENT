import json
import subprocess
from datetime import datetime
from langchain.tools import tool


SNAPSHOTS: dict = {} # ip -> mac


@tool
def check_arp_table(container_name: str, compare_with_previous: bool = False):
    """
    проверяет ARP-таблицу контейнера на аномалии

    запускает ip neigh show внутри контейнера,
    если compare_with_previous=True - сравнивает MAC с предыдущим снимком того же контейнера
    
    если MAC для одного и того же IP изменился или появились новые записи — возможен ARP-спуфинг

    в spoofing-контуре используй:
        spoof-victim — жертва
        spoof-target — цель
        spoof-attacker — атакующий

    порядок проверки:
        1) check_arp_table("spoof-victim") - запоминаем начальное состояние                        
        2) run_arp_spoof - атака
        3) check_arp_table("spoof-victim", compare_with_previous=True) - сравниваем 

   
    container_name: имя контейнера
    compare_with_previous: сравнивать с предыдущим состоянием?
    """

    # =========== запускаем ip neigh ===========
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "ip", "neigh", "show"],
            capture_output=True,
            text=True,
            timeout=10)
    except FileNotFoundError:
        return "docker не установлен"
    except Exception as e:
        return f"возникла ошибка: {e}"

    if result.returncode != 0: # контейнер не существует или ip недоступен
        stderr = (result.stderr or "").strip()[:100]
        return f"в {container_name} возникла ошибка: {stderr}"

    # =========== парсим ip neigh ===========
    new_snapshots = {} # ip -> mac
    entries = []

    for line in result.stdout.strip().splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue

        ip = parts[0]
        mac = None
        if "lladdr" in parts: # для сравнения нужны только записи с lladdr
            idx = parts.index("lladdr")
            if idx + 1 < len(parts): mac = parts[idx + 1]

        # любое стандартное состояние
        state = "UNKNOWN"
        for s in ("REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "INCOMPLETE", "PERMANENT"):
            if s in parts:
                state = s
                break
        if mac:
            new_snapshots[ip] = mac
            entries.append({"ip": ip, "mac": mac, "state": state})

    # =========== сравниваем с предыдущем состоянием ===========
    anomalies = []
    previous = SNAPSHOTS.get(container_name, {})

    if compare_with_previous and container_name in SNAPSHOTS:
        for ip, mac in new_snapshots.items():
            if ip in previous and previous[ip] != mac: # MAC изменился
                anomalies.append({
                    "ip": ip,
                    "old_mac": previous[ip],
                    "new_mac": mac,
                    "severity": "HIGH",
                    "reason": "MAC изменился - возможен ARP-спуфинг"})
        for ip, mac in new_snapshots.items():
            if ip not in previous: # появились новые записи
                anomalies.append({
                    "ip": ip,
                    "old_mac": None,
                    "new_mac": mac,
                    "severity": "MEDIUM",
                    "reason": "появилась новая запись в ARP-таблице - возможен ARP-спуфинг"})

    # сохраняем текущее состояние 
    SNAPSHOTS[container_name] = dict(new_snapshots)

    # =========== формируем результат ===========
    if not compare_with_previous:
        verdict = "закрелено начальное состояние таблицы"
    elif anomalies:
        verdict = "найдены аномалии"
    else:
        verdict = "OK"

    summary = {
        "container": container_name,
        "verdict": verdict,
        "total_entries": len(entries),
        "entries": entries,
        "anomalies": anomalies}

    return json.dumps(summary, ensure_ascii=False, indent=2)