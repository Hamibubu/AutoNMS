from netmiko import ConnectHandler
import re, csv

R1 = {
    'device_type': 'cisco_ios_telnet',
    'ip': '4.4.4.1',
    'username': 'netadmin',
    'password': 'Passw0rd',
    'port': 23,  # Telnet port
}

R2 = {
    'device_type': 'cisco_ios_telnet',
    'ip': '4.4.4.2',
    'username': 'netadmin',
    'password': 'Passw0rd',
    'port': 23,  # Telnet port
}

R3 = {
    'device_type': 'cisco_ios_telnet',
    'ip': '4.4.4.3',
    'username': 'netadmin',
    'password': 'Passw0rd',
    'port': 23,  # Telnet port
}

R4 = {
    'device_type': 'cisco_ios_telnet',
    'ip': '4.4.4.4',
    'username': 'netadmin',
    'password': 'Passw0rd',
    'port': 23,  # Telnet port
}

R5 = {
    'device_type': 'cisco_ios_telnet',
    'ip': '4.4.4.5',
    'username': 'netadmin',
    'password': 'Passw0rd',
    'port': 23,  # Telnet port
}

devices = [R1,R2,R3,R4,R5]

class AutoNMS:
    def __init__(self, devices):
        self.devices = devices
    
    def showIPAM(self):
        data = {}
        for device in self.devices:
            try:
                with ConnectHandler(**device) as conn:
                    # Obtener el hostname
                    hostname_output = conn.send_command_timing("show whoami")
                    hostname_match = re.search(r"Comm Server \"(R\d+)\"", hostname_output)
                    hostname = hostname_match.group(1) if hostname_match else "Unknown"

                    # Obtener información de las interfaces
                    interfaces_output = conn.send_command("show ip interface brief")
                    interfaces_data = self.parseInterfaces(interfaces_output)

                    # Almacenar la información en el diccionario
                    data[hostname] = {
                        'interfaces': interfaces_data,
                    }

                    # Imprimir la información
                    print(f"Información para {hostname}:")
                    print("Interfaces:")
                    for interface, ip in interfaces_data.items():
                        print(f"Interface: {interface}, IP: {ip}")
                    print("\n")

            except Exception as e:
                print(f"Error en la conexión a {device['ip']}: {e}")

        return data

    def parseInterfaces(self, output):
        ip_data = {}
        ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        lines = output.splitlines()
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                interface = parts[0]
                ip_match = re.search(ip_regex, line)
                ip = ip_match.group() if ip_match else "N/A"
                ip_data[interface] = ip
        return ip_data

    def saveIPAM(self, filename='ipam.csv'):
        ipam_data = self.showIPAM()
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Hostname', 'Interface', 'IP Address'])
            for hostname, data in ipam_data.items():
                interfaces_data = data['interfaces']
                for interface, ip in interfaces_data.items():
                    writer.writerow([hostname, interface, ip])

    def confManager(self):
        for device in self.devices:
            try:
                pass
            except Exception as e:
                print(f"Error en la conexión a {device['ip']}: {e}")

auto_nms = AutoNMS(devices)
auto_nms.saveIPAM()