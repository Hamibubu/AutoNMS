from netmiko import ConnectHandler
from datetime import datetime
import re, csv, os, json, threading, logging, socket, docx

rojo = "\033[1;31m"
verde = "\033[1;32m"
amarillo = "\033[1;33m"
azul = "\033[1;34m"
reset = "\033[0;0m"

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
        print(ipam_data)
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Hostname', 'Interface', 'IP Address'])
            for hostname, data in ipam_data.items():
                interfaces_data = data['interfaces']
                for interface, ip in interfaces_data.items():
                    writer.writerow([hostname, interface, ip])

    def menuIPAM(self):
        while True:
            print("[+] Menú de IPAM:")
            print("1. Mostrar solamente el IPAM.")
            print("2. Guardar los datos.")
            print("3. Salir.")

            opcion = input("Selecciona una opción (1/2/3) > ")

            if opcion == '1':
                self.showIPAM()
            elif opcion == '2':
                self.saveIPAM()
            elif opcion == '3':
                print("Saliendo del menú de IPAM.")
                break
            else:
                print("Opción no válida. Por favor, selecciona una opción válida.")

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
        if device['device_type'] != "cisco_ios_telnet":
            print("Tipo de dispositivo no válido. Se establecerá 'unknown' como tipo de dispositivo.")
            device['device_type'] = "unknown"
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

    def confMenu(self):
        while True:
            print("[+] Menú de Configuración:")
            print("1. Configuración específica.")
            print("2. Configuración para todos los routers.")
            print("3. Salir.")

            opcion = input("Selecciona una opción (1/2/3) > ")

            if opcion == '1':
                self.sendConfigSpecific()
            elif opcion == '2':
                self.sendConfigAll()
            elif opcion == '3':
                print("Saliendo del menú de Configuración.")
                break
            else:
                print("Opción no válida. Por favor, selecciona una opción válida.")


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
        print(f"Servidor syslog escuchando en 192.168.174.1:{514} (Presiona CTRL+C para salir)")

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

    def showOptionsSyslog(self):
        while True:
            print("[+] Menú de Syslog:")
            print("1. Iniciar Syslog Listener.")
            print("2. Obtener logs del router.")
            print("3. Salir.")

            opcion = input("Selecciona una opción (1/2/3) > ")

            if opcion == '1':
                syslog_thread = threading.Thread(target=self.syslogListener)
                syslog_thread.start()

                try:
                    # Esperar a que el usuario presione Ctrl+C
                    while True:
                        pass
                except KeyboardInterrupt:
                    print("Deteniendo el servidor syslog...")
                    self.stopSyslogListener()

                # Esperar a que el hilo del servidor syslog termine
                syslog_thread.join()
                print("Servidor syslog detenido.")
                
            elif opcion == '2':
                self.getCiscoLogs()

            elif opcion == '3':
                print("Saliendo del menú de Syslog.")
                break
            else:
                print("Opción no válida. Por favor, selecciona una opción válida.")

    def is_critical_error(self, message):
        # Revisa si el mensaje contiene indicadores de error crítico
        critical_keywords = ["CRITICAL", "ERROR", "ALERT", "EMERGENCY", "FAILED", " %LINEPROTO-5-UPDOWN"]
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

    def complianceSecurity(self):
        while True:
            print("[+] ¿Qué quieres verificar?:")
            print("1. Checar si hay protocolos de ruteo no autorizados.")
            print("2. Checar seguridad del ssh.")
            print("3. Checar si Fa 0/0 está apagada.")
            print("4. Salir")

            opcion = input("Selecciona una opción (1/2/3/4) >  ")

            if opcion == '1':
                self.checkRouting()
            elif opcion == '2':
                self.checkSSH()
            elif opcion == '3':
                self.verifyFA()
            elif opcion == '4':
                break
            else:
                print("Opción no válida. Por favor, selecciona una opción válida.")

        
    def checkRouting(self):
        contin = True
        protocolos = []
        while contin:
            protocolo_auth = str(input("[+] Introduce el protocolo o los protocolos de ruteo autorizados: ")).lower()
            protocolos.append(protocolo_auth)
            seguir = str(input("[!] Quieres agregar otro? (si - no): "))
            seguir = seguir.lower()
            if (seguir != "si"):
                print("[+] Revisando...")
                contin = False
        for device in self.devices:
            try:
                # Obtener el hostname del dispositivo
                hostname = self.get_hostname(device)

                with ConnectHandler(**device) as conn:
                    # Obtener la configuración del dispositivo y guardarla en un archivo
                    conn.enable()
                    output = conn.send_command_timing('show ip protocols')

                patron = r'Routing Protocol is "([^"]*)"'

                resultados = re.findall(patron, str(output))

                if resultados:
                    for resultado in resultados:
                        partes = resultado.split(' ')
                        if len(partes) == 2:
                            protocolo, numero = partes
                        if protocolo not in protocolo_auth:
                            print(f"[+] Protocolo no autorizado encontrado {resultado} en {hostname}")
                            option = str(input("[+] ¿Deseas eliminarlo? (si - no): ")).lower()
                            if option != "no":
                                print(f"[+] Eliminando {resultado} en {hostname}...")
                                comando = ["no router "+resultado,"end","wr"]
                                try:
                                    with ConnectHandler(**device) as conn:
                                        conn.enable()  
                                        output = conn.send_config_set(comando)
                                        print(output)
                                        output = output.split('\n')
                                        for line in output:
                                            if "^" in line:
                                                print("[!] Error en este comando: "+str(temp))
                                            temp = line
                                        
                                except Exception as e:
                                    print(f"[!] Error en la conexión a {device['ip']}: {e}")
                                break
                    print(f"[+] Chequeo terminado parece estar todo bien en {hostname}...")                
                else:
                    print(f"[+] No hay protocolos de ruteo en {hostname}")

            except Exception as e:
                print(f"Error en la conexión a {device['ip']}: {e}")

    def checkSSH(self):
        for device in self.devices:
            try:
                # Obtener el hostname del dispositivo
                hostname = self.get_hostname(device)

                with ConnectHandler(**device) as conn:
                    # Obtener la configuración del dispositivo y guardarla en un archivo
                    conn.enable()
                    output = conn.send_command_timing('show ip ssh')

                # Regex para extraer la versión de SSH
                version_ssh_regex = r"SSH Enabled - version (\d+\.\d+)"
                version_ssh = re.search(version_ssh_regex, output)
                if version_ssh:
                    version_ssh = version_ssh.group(1)

                # Regex para extraer el tamaño mínimo de la clave Diffie Hellman
                dh_size_regex = r"Minimum expected Diffie Hellman key size : (\d+) bits"
                dh_size = re.search(dh_size_regex, output)
                if dh_size:
                    dh_size = dh_size.group(1)

                print(f"Versión SSH: {version_ssh}")
                print(f"Tamaño de clave Diffie Hellman: {dh_size} bits")

                if int(dh_size) < 2048:
                    print(f"[+] Tamaño de bits inseguro {dh_size} bits, se recomienda user 2048 bits")
                    change = str(input("[+] ¿Deseas cambiar el tamaño?: ")).lower()
                    if change != "no":
                        print(f"[+] Agregando el requisito de 2048 bits en {hostname}...")
                        comando = ["ip ssh dh min size 2048","end","wr"]
                        try:
                            with ConnectHandler(**device) as conn:
                                conn.enable()  
                                output = conn.send_config_set(comando)
                                print(output)
                                output = output.split('\n')
                                for line in output:
                                    if "^" in line:
                                        print("[!] Error en este comando: "+str(temp))
                                    temp = line
                        except Exception as e:
                            print(f"[!] Error en la conexión a {device['ip']}: {e}")
                if str(version_ssh) != "2.0":
                    print(f"[+] Versión de ssh no es segura...")
                    change = str(input("[+] ¿Deseas cambiarla?: ")).lower()
                    if change != "no":
                        print(f"[+] Agregando ssh version 2 {hostname}...")
                        comando = ["ip ssh version 2","end","wr"]
                        try:
                            with ConnectHandler(**device) as conn:
                                conn.enable()  
                                output = conn.send_config_set(comando)
                                print(output)
                                output = output.split('\n')
                                for line in output:
                                    if "^" in line:
                                        print("[!] Error en este comando: "+str(temp))
                                    temp = line
                        except Exception as e:
                            print(f"[!] Error en la conexión a {device['ip']}: {e}")
                print(f"[+] Chequeo terminado parece estar todo bien en {hostname}...")                
            except Exception as e:
                print(f"Error en la conexión a {device['ip']}: {e}")
        
    def verifyFA(self):
        for device in self.devices:
            try:
                # Obtener el hostname del dispositivo
                hostname = self.get_hostname(device)

                with ConnectHandler(**device) as conn:
                    # Obtener la configuración del dispositivo y guardarla en un archivo
                    conn.enable()
                    output = conn.send_command_timing('show ip ssh')

                if "down" not in output:
                    print(f"[!] La interface de Fa0/0 parece estar activa en {hostname} ...") 
                    change = str(input("[+] ¿Deseas apagarla?: ")).lower()
                    if change != "no":
                        print(f"[+] Agregando Fa0/0 en {hostname}...")
                        comandos = ["interface FastEthernet0/0","shutdown","end","wr"]
                    try:
                        with ConnectHandler(**device) as conn:
                            conn.enable()  
                            output = conn.send_config_set(comandos)
                            print(output)
                            output = output.split('\n')
                            for line in output:
                                if "^" in line:
                                    print("[!] Error en este comando: "+str(temp))
                                temp = line
                    except Exception as e:
                        print(f"[!] Error en la conexión a {device['ip']}: {e}")
            except Exception as e:
                print(f"Error en la conexión a {device['ip']}: {e}")

    def generateReport(self, output_file):
        try:
            # Crear un documento de Word
            doc = docx.Document()

            # Título del informe
            doc.add_heading('Informe de Red', 0)

            # Fecha del informe
            fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            doc.add_paragraph(f"Fecha del Informe: {fecha}")

            # Recopilar información de los dispositivos
            for device in self.devices:
                try:
                    # Obtener el hostname del dispositivo
                    hostname = self.get_hostname(device)

                    with ConnectHandler(**device) as conn:
                        # Obtener la configuración del dispositivo
                        conn.enable()
                        interfaces = conn.send_command_timing('show ip interface brief')
                        routing_prots = conn.send_command_timing('show ip protocols')
                        arp = conn.send_command_timing('show arp')
                        cpu = conn.send_command_timing('show processes cpu history')
                        power = conn.send_command_timing('show environment all')
                        config = conn.send_command_timing('show running-config')

                    # Agregar información del dispositivo al documento de Word
                    doc.add_heading(f"Información de {hostname}", level=1)
                    doc.add_paragraph(f"Interfaces:\n {interfaces}")
                    doc.add_paragraph(f"Protocolos de Enrutamiento:\n {routing_prots}")
                    doc.add_paragraph(f"Tabla ARP:\n {arp}")
                    doc.add_paragraph(f"Uso de CPU:\n {cpu}")
                    doc.add_paragraph(f"Estado de Energía:\n {power}")
                    doc.add_paragraph(f"Configuración:\n {config}")

                    print(f"[+] Información de {hostname} obtenida...")

                except Exception as e:
                    doc.add_paragraph(f"Error en {hostname}: {str(e)}")

            # Guardar el documento de Word
            doc.save(output_file)

            print(f"Informe Word generado en {output_file}")

        except Exception as e:
            print(f"Error al generar el informe Word: {str(e)}")

def Menu():
    print("[+] Selecciona lo que deseas:")
    print(f"1.- Menú {verde}IPAM{reset}")
    print(f"2.- Menú de {verde}change manager{reset}")
    print(f"3.- Configuration {verde}Manager{reset}")
    print(f"4.- Agregar {verde}ROUTER{reset}")
    print(f"5.- Mostrar opciones de {verde}Syslog{reset}")
    print(f"6.- Compliance {verde}Security{reset}")
    print(f"7.- {verde}Generar Reporte{reset}")
    print(f"8.- {rojo}Salir{reset}")
    choice = int(input("Ingrese una opción: "))
    return choice

def main():
    auto_nms = AutoNMS()
    auto_nms.loadRoutersFromFile()
    while True:
        choice = Menu()
        if choice == 1:
            auto_nms.menuIPAM()
        elif choice == 2:
            auto_nms.confMenu()
        elif choice == 3:
            auto_nms.confManager()
        elif choice == 4:
            auto_nms.addRouter()
        elif choice == 5:
            auto_nms.showOptionsSyslog()
        elif choice == 6:
            auto_nms.complianceSecurity()
        elif choice == 7:
            nombre_arch = str(input("[?] ¿Qué nombre le quieres dar al archivo?\n   > "))
            auto_nms.generateReport(nombre_arch)
        elif choice == 8:
            confirmacion = input("¿Está seguro de que desea salir? (Si/No): ").lower()
            if confirmacion == "si":
                exit()
            else:
                print("Continuando...")
        else:
            print(f"{rojo}Opción inválida{reset}")

if __name__ == "__main__":
    main()
