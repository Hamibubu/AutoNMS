from netmiko import ConnectHandler
from datetime import datetime
import re, csv, os, json

class AutoNMS:
    def __init__(self):
        self.devices = []
    
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
                    print(f"[i] Información para {hostname}:")
                    print("[+]Interfaces:")
                    for interface, ip in interfaces_data.items():
                        print(f"[+] Interface: {interface}, IP: {ip}")
                    print("\n")

            except Exception as e:
                print(f"[!] Error en la conexión a {device['ip']}: {e}")

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
                        print(f"[i] Configuración de {hostname} ha cambiado y se ha guardado en {config_filename}")
                    else:
                        print(f"[i] Configuración de {hostname} no ha cambiado, no se guarda nada.")
                else:
                    # No hay configuraciones anteriores, guardar la configuración actual
                    with open(config_filename, 'w') as config_file:
                        config_file.write(config_output)
                    print(f"[i] Configuración de {hostname} guardada en {config_filename}")

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
            print(f"[!] Error obteniendo el hostname de {device['ip']}: {e}")
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
    
    def addRouter(self):
        print("Agregar un nuevo router manualmente:")
        device = {}
        device['device_type'] = input("[+] Ingrese el tipo de dispositivo (e.g., cisco_ios_telnet): ")
        device['ip'] = input("[+] Ingrese la dirección IP del dispositivo: ")
        device['username'] = input("[+] Ingrese el nombre de usuario: ")
        device['password'] = input("[+] Ingrese la contraseña: ")
        device['port'] = int(input("[+] Ingrese el número de puerto (e.g., 23): "))
        device['secret'] = input("[+] Ingrese la contraseña secreta (o presione Enter si no hay): ")

        with open('routers.json', 'r') as file:
            existing_devices = json.load(file)

        existing_devices.append(device)

        with open('routers.json', 'w') as file:
            json.dump(existing_devices, file, indent=4)

        self.devices = existing_devices

    def loadRoutersFromFile(self, filename='routers.json'):
        try:
            with open(filename, 'r') as file:
                self.devices = json.load(file)
                print("[i] Routers cargados desde el archivo.")
        except FileNotFoundError:
            print("[!] El archivo de configuración de routers no existe.")

    def sendConfigAll(self):
        file = str(input("[+] Dame el nombre del archivo sobre el que leer: "))
        commands = self.readCommands(file)
        for device in self.devices:
            try:
                with ConnectHandler(**device) as conn:
                    conn.enable()  
                    output = conn.send_config_set(commands)
                    output = output.split('\n')
                    for line in output:
                        if "^" in line:
                            print("[!] Error en este comando: "+str(temp))
                        temp = line
            except Exception as e:
                print(f"[!] Error en la conexión a {device['ip']}: {e}")

    def sendConfigSpecific(self):
        router_ip = str(input("[+] Dame la IP del router al que se mandará la información: "))
        for device in self.devices:
            if device.get('ip') == router_ip:
                print(f"[+] Router encontrado: {device}")
                file = str(input("[+] Dame el nombre del archivo sobre el que leer: "))
                commands = self.readCommands(file)
                try:
                    with ConnectHandler(**device) as conn:
                        conn.enable()  
                        output = conn.send_config_set(commands)
                        output = output.split('\n')
                        for line in output:
                            if "^" in line:
                                print("[!] Error en este comando: "+str(temp))
                            temp = line
                except Exception as e:
                    print(f"[!] Error en la conexión a {device['ip']}: {e}")
                break
        else:
            print(f"[!] No se encontró un router con la IP {router_ip}")

    def readCommands(self, archivo):
        commands = []
        try:
            with open(archivo, 'r') as file:
                lines = file.readlines()
                for line in lines:
                    comand = line.strip()
                    commands.append(comand)
        except FileNotFoundError:
            print(f"Archivo no encontrado: {archivo}")
        return commands
    

auto_nms = AutoNMS()
auto_nms.loadRoutersFromFile()
auto_nms.sendConfigSpecific()