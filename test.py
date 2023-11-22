import socket
import time

def send_syslog_message(message, host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        client_socket.sendto(message.encode("utf-8"), (host, port))

if __name__ == "__main__":
    syslog_host = "192.168.174.1"  # Cambia esto a la dirección IP de tu servidor syslog
    syslog_port = 514  # Puerto en el que está escuchando tu servidor syslog

    try:
        while True:
            # Envía un mensaje de syslog de prueba con diferentes severidades
            send_syslog_message("Mensaje de prueba de INFO", syslog_host, syslog_port)
            send_syslog_message("Mensaje de prueba de ERROR", syslog_host, syslog_port)
            send_syslog_message("Mensaje de prueba de CRITICAL", syslog_host, syslog_port)

            time.sleep(5)  # Espera 5 segundos antes de enviar otro mensaje
    except KeyboardInterrupt:
        print("Prueba de syslog detenida.")

