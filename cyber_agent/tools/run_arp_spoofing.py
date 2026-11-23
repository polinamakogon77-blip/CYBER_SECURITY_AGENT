import subprocess
from langchain.tools import tool


@tool
def run_arp_spoof(victim_ip: str = "172.28.0.10", target_ip: str = "172.28.0.20", attacker: str = "spoof-attacker"):
    """
    запускает arp_spoofing в контейнере attacker

    используй для демонстрации ARP-спуфинга в тренировочном контуре

    victim_ip - IP жертвы
    target_ip - IP цели
    attacker - атакующий
    """

    # ========== запуск скрипта ========== 
    try:
        result = subprocess.run(
            ["docker", "exec", "-e", f"VICTIM_IP={victim_ip}",
             "-e", f"TARGET_IP={target_ip}", attacker,
             "timeout", "10", "python3", "/app/arp_spoofing.py"],
            capture_output=True,
            text=True,
            timeout=20)
    except Exception as e:
        return f"возникла ошибка запуска: {e}"

    stdout = (result.stdout or "")[:1000]
    stderr = (result.stderr or "")[:500]

    # GNU timeout returns 124 after the planned ten-second lab run.
    if result.returncode not in (0, 124):
        return (
            f"возникла ошибка запуска (код {result.returncode})\n"
            f"stdout\n{stdout}\nstderr\n{stderr}"
        )

    return (
        f"был запущен ARP-spoofing\n"
        f"victim: {victim_ip}\n"
        f"target: {target_ip}\n"
        f"attacker: {attacker}\n"
        f"stdout\n{stdout}\n"
        f"stderr\n{stderr}"
    )