# Detector de ARP Spoofing

Herramienta académica de detección de ataques ARP spoofing/poisoning en redes locales (LAN), desarrollada en Python con Scapy, expuesta a través de un backend web en Flask.

## Aviso importante

Este proyecto es estrictamente defensivo. Monitorea de forma pasiva el tráfico ARP de la red para detectar anomalías (una IP asociada a más de una dirección MAC). No realiza spoofing, no envía paquetes falsificados y no bloquea ni corta el acceso de ningún dispositivo. Fue desarrollado con fines educativos para un proyecto universitario de redes.

## Cómo funciona

El programa escucha pasivamente las respuestas ARP (ARP Reply) que circulan por la red y construye una tabla de confianza propia (IP -> MAC). Si una IP que ya conocía aparece de repente asociada a una MAC distinta, genera una alerta -- ese es el patrón característico que deja un ataque de ARP spoofing.

## Arquitectura

.
├── app.py              # Servidor Flask: expone la API y sirve el frontend
├── sniffer.py           # Lógica de captura y detección con Scapy (independiente del servidor)
├── requirements.txt     # Dependencias del proyecto
└── templates/
    └── index.html        # Frontend mínimo (consulta la API vía fetch)

La lógica de red (Scapy) está separada del servidor web (Flask) a propósito: sniffer.py no depende de Flask para nada, lo que permite reemplazar o mejorar el frontend sin tocar la lógica de detección.

## Requisitos

- Python 3.10 o superior
- Npcap (https://npcap.com/#download) -- necesario en Windows para que Scapy pueda capturar paquetes; instalar con la opción "WinPcap API-compatible Mode" activada
- Permisos de administrador para ejecutar el programa (necesarios para la captura de paquetes en bruto)

## Instalación

git clone https://github.com/TU-USUARIO/TU-REPOSITORIO.git
cd TU-REPOSITORIO
python -m venv venv
venv\Scripts\activate          (en Windows)
pip install -r requirements.txt

## Uso

Abre una terminal como administrador y ejecuta:

python app.py

Luego abre en tu navegador:

http://127.0.0.1:5000

La página mostrará en tiempo real:
- Estado del monitoreo (activo/detenido)
- Tabla de confianza (IP -> MAC) construida en vivo
- Alertas de posibles intentos de ARP spoofing detectados

## API disponible

/api/status   (GET)   -> Indica si el sniffer está corriendo
/api/table    (GET)   -> Devuelve la tabla de confianza actual (IP -> MAC)
/api/alerts   (GET)   -> Devuelve la lista de alertas detectadas
/api/start    (POST)  -> Inicia el monitoreo
/api/stop     (POST)  -> Detiene el monitoreo

## Seguridad al desplegar

Esta API no tiene autenticación. Si decides exponerla más allá de tu red local (por ejemplo, accesible desde Internet), cualquiera podría ver la tabla de red de tu dispositivo o controlar el sniffer remotamente. Se recomienda mantenerlo únicamente dentro de una red local de confianza, o agregar autenticación antes de exponerlo públicamente.

## Limitaciones conocidas

- En redes Wi-Fi, la visibilidad de tráfico ARP unicast entre otros dispositivos es limitada (limitación del modo de captura en hardware Wi-Fi común, no del código).
- La herramienta puede generar falsos positivos ante cambios legítimos de MAC (por ejemplo, un router que reinicia su tarjeta de red).

## Autor

Proyecto universitario -- Informática.

## Licencia

Uso educativo.