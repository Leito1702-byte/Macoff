"""
Servidor web del detector de ARP spoofing y escaneo de dispositivos.
"""

from flask import Flask, jsonify, render_template
from sniffer import ArpWatcher

app = Flask(__name__)
watcher = ArpWatcher()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def status():
    return jsonify({"corriendo": watcher.is_running()})


@app.route("/api/table")
def table():
    return jsonify(watcher.get_table())


@app.route("/api/alerts")
def alerts():
    return jsonify(watcher.get_alerts())


@app.route("/api/devices")
def devices():
    return jsonify(watcher.get_connected_devices())


@app.route("/api/scan", methods=["POST"])
def scan():
    # Ejecuta el escaneo activo en la subred de tu casa (ajusta el rango si es necesario)
    dispositivos = watcher.escanear_red_activa("192.168.1.0/24")
    return jsonify({"ok": True, "encontrados": len(dispositivos), "dispositivos": dispositivos})


@app.route("/api/start", methods=["POST"])
def start():
    watcher.start()
    return jsonify({"ok": True})


@app.route("/api/stop", methods=["POST"])
def stop():
    watcher.stop()
    return jsonify({"ok": True})


if __name__ == "__main__":
    watcher.start()
    app.run(debug=True, use_reloader=False)