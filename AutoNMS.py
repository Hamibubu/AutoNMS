from netmiko import ConnectHandler
from datetime import datetime
import re, csv, os, json, threading, signal, sys, logging, socket

class AutoNMS:
    def __init__(self):
        self.devices = []
        self.server_socket = None
        self.run = True
    
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
    
    def syslogListener(self):

        high_severity = []
        log_folder = "syslog"
        log_file = os.path.join(log_folder, "syslog.log")
        
        os.makedirs(log_folder, exist_ok=True)
        
        logging.basicConfig(filename=log_file, level=logging.INFO, format='%(message)s')

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind(("192.168.174.1", 514))
        print(f"Servidor syslog escuchando en 192.168.174.1:{514}")

        while self.run:
            try:
                data, addr = self.server_socket.recvfrom(1024)  # Tamaño del búfer
                message = data.decode("utf-8")
                print(f"[+] Mensaje de syslog recibido de {addr}: {message}")
                logging.info(message)
                if self.is_critical_error(message):
                    high_severity.append(message)
                    print("[!] Evento de severidad alta detectado.")
            except OSError:
                self.run=False
                self.handleShutdown(high_severity)

    def get_last_5_logs(self):
        log_file = os.path.join("syslog", "syslog.log")
        with open(log_file, 'r') as file:
            lines = file.readlines()
        last_5_logs = lines[-5:]
        return last_5_logs

    def handleShutdown(self, high_severity):
        print("\nDeteniendo el servidor syslog...")
        last5 = self.get_last_5_logs()
        print(last5)
        self.generate_csv(high_severity, "high_severity_logs.csv")
        print("Archivo generado: high_severity_logs.csv")
    
    def generate_csv(self, logs, filename):
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Log Message'])
            for log in logs:
                writer.writerow([log])

    def stopSyslogListener(self):
        self.should_run = False
        if self.server_socket:
            self.server_socket.close()

    def is_critical_error(self, message):
        # Revisa si el mensaje contiene indicadores de error crítico
        critical_keywords = ["CRITICAL", "ERROR", "ALERT", "EMERGENCY", "FAILED", "UPDOWN"]
        severity_levels = ["%0-", "%1-", "%2-"]
        return any(keyword in message for keyword in critical_keywords) or any(message.startswith(level) for level in severity_levels)    

    def getCiscoLogs(self):
        high_severity = []
        for device in self.devices:
            try:
                # Obtener el hostname del dispositivo
                hostname = self.get_hostname(device)

                # Crear una carpeta con el nombre del hostname si no existe
                folder_path = f"syslog/{hostname}"
                os.makedirs(folder_path, exist_ok=True)

                with ConnectHandler(**device) as conn:
                    # Obtener la configuración del dispositivo y guardarla en un archivo
                    conn.enable()
                    syslog_output = conn.send_command_timing('show logging')

                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                syslog_filename = f"{folder_path}/syslog_{timestamp}.txt"

                with open(syslog_filename, 'w') as syslog_file:
                    syslog_file.write(syslog_output)
                print(f"[i] Configuración de {hostname} guardada en {syslog_filename}")
                # Verificar si hay errores críticos en los logs
                for log_line in syslog_output.splitlines():
                    if self.is_critical_error(log_line):
                        print(f"Error crítico encontrado en {hostname}: {log_line}")
                        high_severity.append(str(hostname)+str(log_line))
                
                print("[i] Últimos 5 logs")

                for error in syslog_output.splitlines()[-5:]:
                    print(error)

                self.generate_csv(high_severity, "high_severity_logs.csv")

            except Exception as e:
                print(f"Error en la conexión a {device['ip']}: {e}")

def main():
    auto_nms = AutoNMS()
    auto_nms.loadRoutersFromFile()
    auto_nms.getCiscoLogs()
    """
    # Iniciar el hilo del servidor syslog
    syslog_thread = threading.Thread(target=auto_nms.syslogListener)
    syslog_thread.start()

    try:
        # Esperar a que el usuario presione Ctrl+C
        while True:
            pass
    except KeyboardInterrupt:
        print("Deteniendo el servidor syslog...")
        auto_nms.stopSyslogListener()

    # Esperar a que el hilo del servidor syslog termine
    syslog_thread.join()
    print("Servidor syslog detenido.")
    """

if __name__ == "__main__":
    main()



