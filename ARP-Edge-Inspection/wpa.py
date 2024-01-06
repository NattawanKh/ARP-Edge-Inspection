import paramiko

def ssh_into_rpi(hostname, username, password, command):
    try:
        # Create an SSH client
        ssh_client = paramiko.SSHClient()

        # Automatically add the server's host key
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the Raspberry Pi
        ssh_client.connect(hostname, username=username, password=password)

        # Run the command with sudo
        sudo_command = f"echo '{password}' | sudo -S {command}"
        stdin, stdout, stderr = ssh_client.exec_command(sudo_command)

        # Get the output of the command
        result = stdout.read().decode('utf-8')

        # Print the command output
        print(result)

        # Close the SSH connection
        ssh_client.close()

    except Exception as e:
        print(f"An error occurred: {str(e)}")

# Replace these values with your Raspberry Pi's details
hostname = "192.168.137.208"
username = "trinity"
password = "trinity"

# Run the sudo command remotely
ssh_into_rpi(hostname, username, password, 'sudo cat /etc/wpa_supplicant/wpa_supplicant.conf | grep "ssid"')
