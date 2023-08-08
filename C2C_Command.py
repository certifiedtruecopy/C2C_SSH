import paramiko
import datetime
import time



def display_menu():
    print("\nCertified True Copy")
    print("=" * 30)
    print("1: Server Security")
    print("2: User Management")
    print("3: Server Management")
    print("4: Install Website")
    print("99: Exit")
    print("=" * 30)



def server_security_menu(client):
    while True:
        print("\nServer Security")
        print("1: Change SSH Port")
        print("99: Back to Main Menu")

        choice = input("Enter your choice: ")
        if choice == '1':
            change_ssh_port(client)
        elif choice == '99':
            return
        else:
            print("Invalid choice. Please try again.")
            server_security_menu(client)

def user_management_menu(client):
    while True:
        print("\nUser Management")
        print("1: Add user")
        print("2: Delete user")
        print("3: Change user password")
        print("4: List of users")
        print("99: Back to Main Menu")

        choice = input("Enter your choice: ")
        if choice == '1':
            add_user(client)
        elif choice == '2':
            delete_user(client)
        elif choice == '3':
            change_user_password(client)
        elif choice == '4':
            list_users(client)
        elif choice == '99':
            return
        else:
            print("Invalid choice. Please try again.")
            user_management_menu(client)


def server_management_menu(client):
    while True:
        print("\nServer Management")
        print("1: Tunnel Setup")
        print("2: UDPGW")
        print("3: Block Domains")
        print("4: Active user limit")
        print("99: Back to Main Menu")

        choice = input("Enter your choice: ")
        if choice == '1':
            tunnel_setup(client)
        elif choice == '2':
            setup_udpgw(client)
        elif choice == '3':
            block_domains(client)
        elif choice == '4':
            activate_user_limit(client)
        elif choice == '99':
            return
        else:
            print("Invalid choice. Please try again.")
            server_management_menu(client)


def install_website_menu(client):
    while True:
        print("\nInstall Website")
        print("1: Install Nginx")
        print("2: Upload Website")
        print("3: Certbot + SSL")
        print("99: Back to Main Menu")

        choice = input("Enter your choice: ")
        if choice == '1':
            install_nginx(client)
        elif choice == '2':
            upload_website(client)
        elif choice == '3':
            install_certbot_and_get_ssl(client)
        elif choice == '99':
            return
        else:
            print("Invalid choice. Please try again.")
            install_website_menu(client)


def perform_action(client, choice):
    if choice == '1':
        server_security_menu(client)
    elif choice == '2':
        user_management_menu(client)
    elif choice == '3':
        server_management_menu(client)
    elif choice == '4':
        install_website_menu(client)
    elif choice == '99':
        print("Exiting.")
        exit(0)
    else:
        print("Invalid choice. Please try again.")


def add_user(client):
    username = input("Please enter your username with a special word at the beginning: ")
    password = input("Enter password: ")
    expiry_days = int(input("Enter the number of days until expiry: "))
    traffic_limit = int(input("Enter traffic limit in GB: "))
    if traffic_limit == 0:
        print('Invalid traffic limit!')
        return
    max_connections = int(input("Enter the maximum number of concurrent connections: "))

    # Calculate expiry date based on number of days
    expiry_date = (datetime.datetime.now() + datetime.timedelta(days=expiry_days)).strftime('%Y-%m-%d')

    # Create new user
    stdin, stdout, stderr = client.exec_command(f'sudo useradd -s /usr/sbin/nologin {username}')
    errors = stderr.read().decode()
    if errors:
        print(f'Error creating user: {errors}')
        return

    # Set user password
    stdin, stdout, stderr = client.exec_command(f'echo "{username}:{password}" | sudo chpasswd')
    errors = stderr.read().decode()
    if errors:
        print(f'Error setting user password: {errors}')
        return

    # Set user expiry date
    stdin, stdout, stderr = client.exec_command(f'sudo chage -E "{expiry_date}" {username}')
    errors = stderr.read().decode()
    if errors:
        print(f'Error setting user expiry date: {errors}')
        return

    # Set user traffic limit
    traffic_limit_bytes = int(traffic_limit) * 1000000000  # Convert GB to Bytes
    stdin, stdout, stderr = client.exec_command(f'sudo iptables -A OUTPUT -p tcp -m owner --uid-owner {username} -m quota --quota {traffic_limit_bytes} -j ACCEPT')
    errors = stderr.read().decode()
    if errors:
        print(f'Error setting user traffic limit: {errors}')
        return

    # Check if users.csv exists and create if not
    stdin, stdout, stderr = client.exec_command('if [ ! -f /var/log/users.csv ]; then echo "user,max_conn" | sudo tee /var/log/users.csv; fi')
    errors = stderr.read().decode()
    if errors:
        print(f'Error creating users.csv file: {errors}')
        return

    # Update users.csv file
    command = f'echo "{username},{max_connections}" | sudo tee -a /var/log/users.csv'
    stdin, stdout, stderr = client.exec_command(command)
    errors = stderr.read().decode()
    if errors:
        print(f'Error updating users.csv file: {errors}')
        return

    print(f'Successfully created user {username}')


def delete_user(client):
    username = input("Enter username to delete: ")
    if not username:
        print("Username cannot be empty!")
        return

    # Delete user
    stdin, stdout, stderr = client.exec_command(f'sudo userdel {username}')
    errors = stderr.read().decode()
    if errors:
        print(f'Error deleting user: {errors}\n')
        return

    print(f'Successfully deleted user {username}\n')

def change_user_password(client):
    username = input("Enter username: ")
    if not username:
        print("Username cannot be empty!")
        return
    new_password = input("Enter new password: ")
    if not new_password:
        print("Password cannot be empty!")
        return

    # Change user password
    stdin, stdout, stderr = client.exec_command(f'echo "{username}:{new_password}" | sudo chpasswd')
    errors = stderr.read().decode()
    if errors:
        print(f'Error changing user password: {errors}\n')
        return

    print(f'Successfully changed password for user {username}\n')


def list_users(client):
    # Ask the user for the username prefix
    username_prefix = input("Please enter the username prefix:")

    print("\n{:<20} {:<20} {:<20} {:<20} {:<20} {:<20}".format("Username", "Production Date", "Expiry Date", "Amount of Traffic", "Traffic Used", "Online User"))
    print("-" * 120)

    # Get the list of users
    stdin, stdout, stderr = client.exec_command('grep "/usr/sbin/nologin" /etc/passwd | cut -d: -f1')
    user_list = stdout.read().decode().split('\n')

    for user in user_list:
        if user and user.startswith(username_prefix):
            # Get the user's information
            stdin, stdout, stderr = client.exec_command(f'sudo chage -l {user}')
            chage_output = stdout.read().decode()

            # Parse the user's information
            created_date = ""
            validity_days = ""
            traffic_limit = ""
            traffic_usage = ""
            online = ""

            lines = chage_output.split('\n')
            for line in lines:
                if "Last password change" in line:
                    created_date = line.split(":")[1].strip()
                elif "Account expires" in line:
                    validity_days = line.split(":")[1].strip()

            # Get the traffic limit and usage for the user
            stdin, stdout, stderr = client.exec_command(f'sudo iptables -v -L OUTPUT')
            iptables_output = stdout.read().decode()

            # Parse the traffic limit and usage information
            lines = iptables_output.split('\n')
            for line in lines:
                if user in line:
                    parts = line.split()
                    traffic_limit = float(parts[14]) / (1000 ** 3)
                    traffic_limit = round(traffic_limit, 2)
                    traffic_usage = parts[1]

            # Check if the user is online
            stdin, stdout, stderr = client.exec_command(f'ps aux | grep "sshd: {user}" | awk "!/priv/" | grep -v grep | wc -l')
            w_output = stdout.read().decode()
            if w_output:
                online = w_output.strip()

            # Print the user's information
            print("{:<20} {:<20} {:<20} {:<20} {:<20} {:<20}".format(user, created_date, validity_days, str(traffic_limit), traffic_usage, online))

    print("-" * 120)

def tunnel_setup(client):
    # Install iptables
    stdin, stdout, stderr = client.exec_command('sudo apt-get install iptables -y')
    errors = stderr.read().decode()
    if errors:
        print(f'Error installing iptables: \n{errors}\n')
    else:
        print('Iptables installation successful')

    # Get IPs
    iranip = input("Enter Iran IP:")
    kharegip = input("Enter Foreign IP:")

    rc_local_path = "/etc/rc.local"
    # Check if the file exists and create if not
    stdin, stdout, stderr = client.exec_command(f'if ! test -f {rc_local_path}; then sudo touch {rc_local_path}; echo "#!/bin/sh -e" | sudo tee {rc_local_path}; echo "exit 0" | sudo tee -a {rc_local_path}; fi')
    errors = stderr.read().decode()
    if errors:
        print(f'Error checking/creating /etc/rc.local: {errors}')
        return

    # Empty the file
    stdin, stdout, stderr = client.exec_command(f'echo "#!/bin/sh -e" | sudo tee {rc_local_path}; echo "exit 0" | sudo tee -a {rc_local_path}')
    errors = stderr.read().decode()
    if errors:
        print(f'Error emptying /etc/rc.local: {errors}')
        return

    rc_local_commands = [
        f"sysctl net.ipv4.ip_forward=1",
        f"iptables -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination {iranip}",
        f"iptables -t nat -A PREROUTING -j DNAT --to-destination {kharegip}",
        f"iptables -t nat -A POSTROUTING -j MASQUERADE",
    ]

    # Add the commands before "exit 0" in the rc.local file
    for command in rc_local_commands:
        stdin, stdout, stderr = client.exec_command(f'sudo sed -i "/exit 0/i {command}" {rc_local_path}')
        errors = stderr.read().decode()
        if errors:
            print(f'Error adding command to rc.local: {errors}')
            return

    # Change permissions of rc.local
    stdin, stdout, stderr = client.exec_command(f"sudo chmod +x {rc_local_path}")
    errors = stderr.read().decode()
    if errors:
        print(f'Error changing permissions of rc.local: {errors}')
        return

    print('Tunnel setup successful')

def setup_udpgw(client):
    import time

    # Check if 'screen' package is installed
    command = 'dpkg -s screen'
    stdin, stdout, stderr = client.exec_command(command)
    errors = stderr.read().decode().strip()
    if errors:
        # If 'screen' is not installed, install it
        command = 'sudo apt-get install -y screen'
        stdin, stdout, stderr = client.exec_command(command)
        errors = stderr.read().decode().strip()
        if errors:  # Check if a real error occurred
            print(f'Error executing command "{command}": {errors}')
            return
        else:
            print('Screen installed successfully')

    # Ask the user for the UDPGW port
    udpgw_port = int(input("Please enter the UDPGW port:"))

    # Kill any processes using the file
    command = 'pkill -f /usr/bin/badvpn-udpgw'
    stdin, stdout, stderr = client.exec_command(command)
    errors = stderr.read().decode()
    if errors:  # Check if a real error occurred
        print(f'Error executing command "{command}": {errors}')
        return

    # Check if the file exists
    command = 'ls /usr/bin/badvpn-udpgw'
    stdin, stdout, stderr = client.exec_command(command)
    file_exists = stdout.read().decode().strip()

    # If the file doesn't exist, download it
    if not file_exists:
        command = 'wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgw64"'
        stdin, stdout, stderr = client.exec_command(command)
        errors = stderr.read().decode()
        if "Saving to" not in errors:  # Check if a real error occurred
            print(f'Error executing command "{command}": {errors}')
            return

    # Wait for the file to download
    time.sleep(8)

    # Create the rc.local file if it doesn't exist
    command = 'touch /etc/rc.local'
    stdin, stdout, stderr = client.exec_command(command)
    errors = stderr.read().decode()
    if errors:  # Check if a real error occurred
        print(f'Error executing command "{command}": {errors}')
        return

    # Create and edit the rc.local file
    rc_local_commands = [
        "#!/bin/sh -e",
        f"screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:{udpgw_port}",
        "exit 0",
    ]
    rc_local_content = "\n".join(rc_local_commands)

    # Write the content to the rc.local file
    command = f'echo "{rc_local_content}" > /etc/rc.local'
    stdin, stdout, stderr = client.exec_command(command)
    errors = stderr.read().decode()
    if errors:
        print(f'Error executing command "{command}": {errors}')
        return

    # Run the final command
    command = f"chmod +x /etc/rc.local && chmod +x /usr/bin/badvpn-udpgw && systemctl daemon-reload && sleep 0.5 && systemctl start rc-local.service && screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:{udpgw_port}"
    stdin, stdout, stderr = client.exec_command(command)
    errors = stderr.read().decode()
    if errors:
        print(f'Error executing command "{command}": {errors}')
        return

    print('UDPGW setup successful')

def block_domains(client):
    # Ask the user to enter the path to the file
    filename = input("Enter the path to the text file containing the domains to block (one per line): ")

    if not filename:
        print('No file selected')
        return

    try:
        # Open the file and read the domains
        with open(filename, 'r') as file:
            domains = file.read().strip().split('\n')

        # Use paramiko's SFTPClient to upload the file
        sftp = client.open_sftp()
        sftp.put(filename, '/tmp/domains.txt')
        sftp.close()

        # Block each domain
        for domain in domains:
            if domain:  # Make sure the domain is not an empty string
                command = f'sudo iptables -A INPUT -s {domain} -j DROP'
                stdin, stdout, stderr = client.exec_command(command)
                errors = stderr.read().decode()
                if errors:
                    print(f'Failed to block domain {domain}: {errors}')
                else:
                    print(f'Successfully blocked domain {domain}')

    except Exception as e:
        print(f'Failed to block domains: {str(e)}')

def activate_user_limit(client):
    command = 'sudo wget -O /var/log/UserLimit.sh https://github.com/certifiedtruecopy/C2C_SSH/raw/main/UserLimit.sh'
    stdin, stdout, stderr = client.exec_command(command)
    errors = stderr.read().decode()
    time.sleep(5)

    # Change the mode of the script to executable
    command = 'sudo chmod +x /var/log/UserLimit.sh'
    stdin, stdout, stderr = client.exec_command(command)
    errors = stderr.read().decode()
    if errors:
        print(f'Error changing script mode: {errors}')
        return

    # Execute the script
    time.sleep(5)
    command = 'nohup sudo bash /var/log/UserLimit.sh > /dev/null 2>&1 &'
    stdin, stdout, stderr = client.exec_command(command)
    errors = stderr.read().decode()
    if errors:
        print(f'Error executing script: {errors}')
        return

    print('UserLimit.sh executed successfully')

def change_ssh_port(client):
    # Ask the user for the new SSH port
    new_ssh_port = int(input("Please enter the new SSH port: "))

    confirm = input("Changing the SSH port will remove any user restrictions. Do you want to continue? (yes/no): ")
    if confirm.lower() == 'yes':
        # Create a temporary copy of the sshd_config file
        backup_command = "sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak"
        stdin, stdout, stderr = client.exec_command(backup_command)

        # Modify the SSH port in the temporary copy of sshd_config
        modify_command = f"sudo sed -i 's/#Port .*/Port {new_ssh_port}/' /etc/ssh/sshd_config.bak"
        stdin, stdout, stderr = client.exec_command(modify_command)

        # Replace the original sshd_config file with the modified one
        replace_command = "sudo mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config"
        stdin, stdout, stderr = client.exec_command(replace_command)

        # Restart the SSH service to apply the changes
        restart_command = "sudo service ssh restart"
        stdin, stdout, stderr = client.exec_command(restart_command)

        print(f'SSH port has been changed to {new_ssh_port}. Please reconnect to the server.')
    else:
        print('SSH port change cancelled by user.')

def install_nginx(client):
    print("Installing Nginx...")
    
    # Always assume the operating system is Debian
    command = 'sudo DEBIAN_FRONTEND=noninteractive apt-get install nginx -y'

    # Execute the installation command
    stdin, stdout, stderr = client.exec_command(command)
    errors = stderr.read().decode()
    if errors:
        print(f'Error installing nginx: {errors}')
        return

    print('Nginx installation successful')

def upload_website(client):
    print("Please provide the path to the zip file of your website:")
    
    filename = input("Path to zip file: ")

    if not filename:
        print('No file provided')
        return

    try:
        # Use paramiko's SFTPClient to upload the file
        sftp = client.open_sftp()
        sftp.put(filename, '/var/www/html/website.zip')
        sftp.close()

        # Wait for 5 seconds
        time.sleep(5)

        # Install unzip
        stdin, stdout, stderr = client.exec_command('sudo DEBIAN_FRONTEND=noninteractive apt-get install unzip -y')
        errors = stderr.read().decode()
        if errors:
            print(f'Error installing unzip: {errors}')
            return

        # Unzip the file
        stdin, stdout, stderr = client.exec_command('unzip /var/www/html/website.zip -d /var/www/html/')
        errors = stderr.read().decode()
        if errors:
            print(f'Error unzipping file: {errors}')
            return

        print('Upload and extraction successful')
    except Exception as e:
        print(f'Failed to upload file: {str(e)}')

def install_certbot_and_get_ssl(client):
    command = 'sudo DEBIAN_FRONTEND=noninteractive apt install certbot python3-certbot-nginx -y'
    print(f"Running command: {command}")
    stdin, stdout, stderr = client.exec_command(command)
    out = stdout.read().decode()
    err = stderr.read().decode()
    print(out)
    print(err)
    time.sleep(20)  # wait for 20 seconds

    domain = input("Please enter your domain: ")
    if not domain:
        print("No domain provided.")
        return

    command = f'sudo DEBIAN_FRONTEND=noninteractive certbot --nginx -d {domain} --register-unsafely-without-email --agree-tos'
    print(f"Running command: {command}")
    stdin, stdout, stderr = client.exec_command(command)
    out = stdout.read().decode()
    err = stderr.read().decode()
    print(out)
    print(err)


def main():
    hostname = input("Enter the server's hostname or IP: ")
    port = int(input("Enter the server's port: "))
    username = input("Enter the username: ")
    password = input("Enter the password: ")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname, port=port, username=username, password=password)

    print("Connected to the server.")
    
    while True:
        display_menu()
        choice = input("Enter your choice (1-7): ")
        perform_action(client, choice)

    client.close()

if __name__ == "__main__":
    main()
