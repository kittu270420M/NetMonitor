from flask import Flask, render_template, send_file
import nmap
import socket
from datetime import datetime
from mac_vendor_lookup import MacLookup
import csv
import os

app = Flask(__name__)

scanner = nmap.PortScanner()
mac_lookup = MacLookup()


# Get network range automatically
def get_network():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()

    network = local_ip.rsplit('.', 1)[0] + ".0/24"

    print("Scanning network:", network)

    return network


# Device type detection
def get_device_type(manufacturer):

    manufacturer = manufacturer.lower()

    if any(x in manufacturer for x in ["apple", "samsung", "xiaomi"]):
        return "Mobile"

    elif any(x in manufacturer for x in ["dell", "lenovo", "hp"]):
        return "Laptop"

    elif "tp-link" in manufacturer:
        return "Router"

    else:
        return "Unknown"


# Scan network
def scan_network():

    network = get_network()

    scanner.scan(hosts=network, arguments="-sn")

    devices = []

    for host in scanner.all_hosts():

        hostname = scanner[host].hostname() or "Unknown"

        mac = "Unknown"
        manufacturer = "Unknown"

        try:

            mac = scanner[host]['addresses']['mac']
            manufacturer = mac_lookup.lookup(mac)

        except:

            pass


        devices.append({

            "ip": host,
            "name": hostname,
            "mac": mac,
            "manufacturer": manufacturer,
            "type": get_device_type(manufacturer),
            "status": "Active",
            "last_seen": datetime.now().strftime("%H:%M:%S")

        })

    return devices


@app.route("/")
def index():

    devices = scan_network()

    return render_template(

        "index.html",

        devices=devices,

        total=len(devices),

        time=datetime.now().strftime("%d %b %Y %H:%M:%S")

    )


@app.route("/export")
def export():

    devices = scan_network()

    filename = "devices.csv"

    with open(filename, "w", newline="") as f:

        writer = csv.writer(f)

        writer.writerow(

            ["IP", "Name", "MAC", "Manufacturer", "Type", "Last Seen"]

        )

        for d in devices:

            writer.writerow(

                [d["ip"], d["name"], d["mac"], d["manufacturer"],
                 d["type"], d["last_seen"]]

            )

    return send_file(filename, as_attachment=True)


if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(

        host="0.0.0.0",
        port=port,
        debug=True

    )
