from flask import Flask, render_template, send_file
import nmap
import socket
from datetime import datetime
from mac_vendor_lookup import MacLookup
import csv

app = Flask(__name__)

scanner = nmap.PortScanner()
mac_lookup = MacLookup()


# ✅ Automatically detect network
def get_network():

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    network = local_ip.rsplit('.', 1)[0] + ".0/24"

    print("Scanning Network:", network)

    return network



# Device type detection
def get_device_type(manufacturer):

    manufacturer = manufacturer.lower()

    if "apple" in manufacturer or "samsung" in manufacturer or "xiaomi" in manufacturer:
        return "Mobile"

    elif "dell" in manufacturer or "lenovo" in manufacturer or "hp" in manufacturer:
        return "Laptop"

    elif "tp-link" in manufacturer or "router" in manufacturer:
        return "Router"

    else:
        return "Unknown"



# Main scan function
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

        device_type = get_device_type(manufacturer)

        devices.append({

            "ip": host,
            "name": hostname,
            "mac": mac,
            "manufacturer": manufacturer,
            "type": device_type,
            "status": "Active",
            "last_seen": datetime.now().strftime("%H:%M:%S")

        })

    return devices



@app.route("/")
def index():

    devices = scan_network()

    total = len(devices)

    time = datetime.now().strftime("%d %b %Y, %H:%M:%S")

    return render_template("index.html",
                           devices=devices,
                           total=total,
                           time=time)



@app.route("/export")
def export():

    devices = scan_network()

    filename = "devices.csv"

    with open(filename, "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow(["IP","Name","MAC","Manufacturer","Type","Last Seen"])

        for d in devices:

            writer.writerow([
                d["ip"],
                d["name"],
                d["mac"],
                d["manufacturer"],
                d["type"],
                d["last_seen"]
            ])

    return send_file(filename, as_attachment=True)



if __name__ == "__main__":

    app.run(debug=True)