"""
Módulo de detección de ARP spoofing y escaneo de red optimizado.
"""

import threading
import time
from scapy.all import sniff, ARP, Ether, srp


class ArpWatcher:
    def __init__(self):
        self._trust_table = {}
        self._alerts = []
        self._connected_devices = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None

    def _procesar_paquete(self, paquete):
        if not paquete.haslayer(ARP) or paquete[ARP].op != 2:
            return

        ip = paquete[ARP].psrc
        mac = paquete[ARP].hwsrc

        with self._lock:
            mac_conocida = self._trust_table.get(ip)

            if mac_conocida is None:
                self._trust_table[ip] = mac
            elif mac_conocida != mac:
                alerta = {
                    "ip": ip,
                    "mac_anterior": mac_conocida,
                    "mac_nueva": mac,
                    "timestamp": time.time(),
                }
                self._alerts.append(alerta)
                self._trust_table[ip] = mac

    def _loop_captura(self):
        sniff(
            store=False,
            filter="arp",
            prn=self._procesar_paquete,
            stop_filter=lambda paquete: self._stop_event.is_set(),
        )

    def escanear_red_activa(self, rango_ip="192.168.1.0/24"):
        """
        Realiza un barrido ARP completo de la subred con un timeout de 3 segundos
        para capturar la mayor cantidad de dispositivos posibles.
        """
        try:
            anuncio = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rango_ip)
            # Aumentamos el timeout a 3 segundos para dar tiempo a dispositivos con ahorro de energía
            respondidos, _ = srp(anuncio, timeout=3, verbose=False)

            dispositivos = []
            for enviado, recibido in respondidos:
                dispositivos.append({
                    "ip": recibido.psrc,
                    "mac": recibido.hwsrc
                })

            with self._lock:
                self._connected_devices = dispositivos
                for d in dispositivos:
                    if d["ip"] not in self._trust_table:
                        self._trust_table[d["ip"]] = d["mac"]

            return dispositivos
        except Exception as e:
            print(f"Error en escaneo activo: {e}")
            return []

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop_captura, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def get_table(self):
        with self._lock:
            return dict(self._trust_table)

    def get_alerts(self):
        with self._lock:
            return list(self._alerts)

    def get_connected_devices(self):
        with self._lock:
            return list(self._connected_devices)