from netmiko import ConnectHandler
from datetime import datetime
import re, csv, os

R1 = {
    'device_type': 'cisco_ios_telnet',
    'ip': '4.4.4.1',
    'username': 'netadmin',
    'password': 'Passw0rd',
    'port': 23,  # Telnet port
    'secret': 'Passw0rd',
}

R2 = {
    'device_type': 'cisco_ios_telnet',
    'ip': '4.4.4.2',
    'username': 'netadmin',
    'password': 'Passw0rd',
    'port': 23,  # Telnet port
    'secret': 'Passw0rd',
}

R3 = {
    'device_type': 'cisco_ios_telnet',
    'ip': '4.4.4.3',
    'username': 'netadmin',
    'password': 'Passw0rd',
    'port': 23,  # Telnet port
    'secret': 'Passw0rd',
}

R4 = {
    'device_type': 'cisco_ios_telnet',
    'ip': '4.4.4.4',
    'username': 'netadmin',
    'password': 'Passw0rd',
    'port': 23,  # Telnet port
    'secret': 'Passw0rd',
}

R5 = {
    'device_type': 'cisco_ios_telnet',
    'ip': '4.4.4.5',
    'username': 'netadmin',
    'password': 'Passw0rd',
    'port': 23,  # Telnet port
    'secret': 'Passw0rd',
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
                # Obtener el hostname del dispositivo
                hostname = self.get_hostname(device)

                # Crear una carpeta con el nombre del hostname si no existe
                folder_path = f"config/{hostname}"
                os.makedirs(folder_path, exist_ok=True)

                with ConnectHandler(**device) as conn:
                    # Obtener la configuración del dispositivo y guardarla en un archivo
                    conn.enable()
                    config_output = conn.send_command('wr t')

                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                config_filename = f"{folder_path}/config_{timestamp}.txt"

                previous_config_file = self.getLatestConfig(folder_path)

                if previous_config_file:
                    # Leer la configuración anterior
                    with open(previous_config_file, 'r') as prev_file:
                        previous_config = prev_file.read()

                    # Comparar la configuración actual con la anterior
                    if config_output != previous_config:
                        # Guardar la configuración actual
                        with open(config_filename, 'w') as config_file:
                            config_file.write(config_output)
                        print(f"Configuración de {hostname} ha cambiado y se ha guardado en {config_filename}")
                    else:
                        print(f"Configuración de {hostname} no ha cambiado, no se guarda nada.")
                else:
                    # No hay configuraciones anteriores, guardar la configuración actual
                    with open(config_filename, 'w') as config_file:
                        config_file.write(config_output)
                    print(f"Configuración de {hostname} guardada en {config_filename}")

            except Exception as e:
                print(f"Error en la conexión a {device['ip']}: {e}")

    def get_hostname(self, device):
        try:
            with ConnectHandler(**device) as conn:
                hostname_output = conn.send_command_timing("show whoami")
                hostname_match = re.search(r"Comm Server \"(R\d+)\"", hostname_output)
                if hostname_match:
                    return hostname_match.group(1)
        except Exception as e:
            print(f"Error obteniendo el hostname de {device['ip']}: {e}")
        return "Unknown"
    
    def getLatestConfig(self, folder_path):
        config_files = [] 
        elements_in_folder = os.listdir(folder_path)
        for element in elements_in_folder:
            if element.startswith("config_"):
                config_files.append(element)
        if config_files:
            return os.path.join(folder_path, max(config_files))
        return None

auto_nms = AutoNMS(devices)
auto_nms.confManager()