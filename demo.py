from netmiko import ConnectHandler

# Define the device parameters
print("*** Creating network Object...")
device = {
    'device_type': 'cisco_ios_telnet',
    'ip': '192.168.100.9',
    'username': 'cisco',
    'password': 'cisco',
    'port': 23,  # Telnet port
}

# Connect to the device
print("*** Connecting to device")
net_connect = ConnectHandler(**device)

# Send a command to the device
print("*** Sending command:")
output = net_connect.send_command('show interface fastEthernet 0/0')

# Print the output
print("*** Output Received:")
outputLines = output.split('\n')

for line in outputLines:
    print(line)


print('\n\n')
print('******************************')
#To find something in the output reding everyline:
for line in outputLines:
    if 'BW 10 Kbit/sec' in line:
        print('10Kb Ethernet Port !!')


print("*** Disconnecting ")
# Disconnect from the device
net_connect.disconnect()