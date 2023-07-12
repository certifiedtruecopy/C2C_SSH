import tkinter as tk
from tkinter import ttk
from ttkbootstrap import Style
import ttkbootstrap as ttkb
import paramiko
import threading
import socket
import time
import psutil
from tkinter import simpledialog
from tkinter import messagebox



def connect_to_server(ip_domain, port, username, password, log_text):
    # Create a new SSH client
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the server
    try:
        client.connect(ip_domain, port=int(port), username=username, password=password)
        log_text.insert('end', 'Successfully connected to the server\n')
        return client
    except Exception as e:
        log_text.insert('end', f'Failed to connect to the server, please check your information and try again\nError: {str(e)}\n')
        return None

def update_server_info(client, cpu_meter, ram_meter, ip4_entry, ip6_entry):
    while True:
        # Get CPU and RAM usage
        cpu_ram_command = "vmstat 1 2 | tail -1 | awk '{print $13,$14}'"
        stdin, stdout, stderr = client.exec_command(cpu_ram_command)
        cpu_user, cpu_system = map(int, stdout.read().decode().split())
        cpu_usage = cpu_user + cpu_system

        ram_command = "free -m | awk 'NR==2{printf \"%.2f\", $3*100/$2 }'"
        stdin, stdout, stderr = client.exec_command(ram_command)
        ram_usage = float(stdout.read().decode().strip())

        cpu_meter.configure(value=cpu_usage)
        ram_meter.configure(value=ram_usage)

        # Get IP addresses
        ip_command = "hostname -I"
        stdin, stdout, stderr = client.exec_command(ip_command)
        ip_addresses = stdout.read().decode().split()
        ip4 = ip_addresses[0]
        ip6 = ip_addresses[1] if len(ip_addresses) > 1 else ''

        ip4_entry.delete(0, tk.END)
        ip4_entry.insert(0, ip4)

        ip6_entry.delete(0, tk.END)
        ip6_entry.insert(0, ip6)

        # Update every second
        time.sleep(1)



def add_user(client, log_text):
    username = simpledialog.askstring("Input", "Enter your username starting with true copy:")
    password = simpledialog.askstring("Input", "Enter password:", show='*')
    expiry_date = simpledialog.askstring("Input", "Enter expiry date (YYYY-MM-DD):")
    traffic_limit = simpledialog.askstring("Input", "Enter traffic limit in GB:")

    # Create new user
    stdin, stdout, stderr = client.exec_command(f'sudo useradd -s /usr/sbin/nologin {username}')
    errors = stderr.read().decode()
    if errors:
        log_text.insert('end', f'Error creating user: {errors}\n')
        return

    # Set user password
    stdin, stdout, stderr = client.exec_command(f'echo "{username}:{password}" | sudo chpasswd')
    errors = stderr.read().decode()
    if errors:
        log_text.insert('end', f'Error setting user password: {errors}\n')
        return

    # Set user expiry date
    stdin, stdout, stderr = client.exec_command(f'sudo chage -E "{expiry_date}" {username}')
    errors = stderr.read().decode()
    if errors:
        log_text.insert('end', f'Error setting user expiry date: {errors}\n')
        return

    # Set user traffic limit
    traffic_limit_bytes = int(traffic_limit) * 1000000000  # Convert GB to Bytes
    stdin, stdout, stderr = client.exec_command(f'sudo iptables -A OUTPUT -p tcp -m owner --uid-owner {username} -m quota --quota {traffic_limit_bytes} -j ACCEPT')
    errors = stderr.read().decode()
    if errors:
        log_text.insert('end', f'Error setting user traffic limit: {errors}\n')
        return

    log_text.insert('end', f'Successfully created user {username}\n')


def delete_user(client, log_text):
    username = simpledialog.askstring("Input", "Enter username to delete:")

    # Delete user
    stdin, stdout, stderr = client.exec_command(f'sudo userdel {username}')
    errors = stderr.read().decode()
    if errors:
        log_text.insert('end', f'Error deleting user: {errors}\n')
        return

    log_text.insert('end', f'Successfully deleted user {username}\n')

def change_user_password(client, log_text):
    username = simpledialog.askstring("Input", "Enter username:")
    new_password = simpledialog.askstring("Input", "Enter new password:", show='*')

    # Change user password
    stdin, stdout, stderr = client.exec_command(f'echo "{username}:{new_password}" | sudo chpasswd')
    errors = stderr.read().decode()
    if errors:
        log_text.insert('end', f'Error changing user password: {errors}\n')
        return

    log_text.insert('end', f'Successfully changed password for user {username}\n')

def list_users(client, log_text, root):
    # Create a new window
    new_window = tk.Toplevel(root)
    new_window.geometry('900x500')

    # Create a treeview
    user_table = ttk.Treeview(new_window)
    user_table["columns"] = ("created", "expires", "traffic_limit", "traffic_used", "online")
    user_table.column("#0", width=120)
    user_table.column("created", width=120)
    user_table.column("expires", width=120)
    user_table.column("traffic_limit", width=120)
    user_table.column("traffic_used", width=120)
    user_table.column("online", width=120)
    user_table.heading("#0", text="Username")
    user_table.heading("created", text="Production Date")
    user_table.heading("expires", text="Expiry Date")
    user_table.heading("traffic_limit", text="Amount of Traffic")
    user_table.heading("traffic_used", text="Traffic Used")
    user_table.heading("online", text="Online")
    user_table.pack(fill='both', expand=True)

    # Get the list of users
    stdin, stdout, stderr = client.exec_command('grep "/usr/sbin/nologin" /etc/passwd | cut -d: -f1')
    user_list = stdout.read().decode().split('\n')

    for user in user_list:
        if user and user.startswith('truecopy'):
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
                    traffic_limit = float(parts[14]) / (1000 ** 3)  # adjust the index based on your iptables command output
                    traffic_limit = round(traffic_limit, 2)  # round to 2 decimal places
                    traffic_usage = parts[1]

            # Check if the user is online
            stdin, stdout, stderr = client.exec_command(f'w -h {user}')
            w_output = stdout.read().decode()
            if w_output:
                online = "Yes"

            # Insert the user's information into the table
            user_table.insert("", tk.END, text=user, values=(created_date, validity_days, traffic_limit,
                                                             traffic_usage, online))
            
def change_ssh_port(client, log_text):
    # Ask the user for the new SSH port
    new_ssh_port = simpledialog.askinteger("Change SSH Port", "Please enter the new SSH port:")

    if messagebox.askyesno("Warning", "Changing the SSH port will remove any user restrictions. Do you want to continue?"):
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

        log_text.insert('end', f'SSH port has been changed to {new_ssh_port}. Please reconnect to the server.\n')
    else:
        log_text.insert('end', 'SSH port change cancelled by user.\n')

def tunnel_setup(client, log_text):
    # Install iptables
    stdin, stdout, stderr = client.exec_command('sudo apt-get install iptables -y')
    errors = stderr.read().decode()
    if errors:
        log_text.insert('end', f'Error installing iptables: \n{errors}\n')
    else:
        log_text.insert('end', 'Iptables installation successful\n')

    # Get IPs
    iranip = simpledialog.askstring("Input", "Enter Iran IP:")
    kharegip = simpledialog.askstring("Input", "Enter Foreign IP:")

    # Setup iptables
    iptables_commands = [
        f"sysctl net.ipv4.ip_forward=1",
        f"iptables -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination {iranip}",
        f"iptables -t nat -A PREROUTING -j DNAT --to-destination {kharegip}",
        f"iptables -t nat -A POSTROUTING -j MASQUERADE",
    ]
    for command in iptables_commands:
        stdin, stdout, stderr = client.exec_command(command)
        errors = stderr.read().decode()
        if errors:
            log_text.insert('end', f'Error setting up iptables: {errors}\n')
            return

    # Check if the file exists and create if not
    rc_local_path = "/etc/rc.local"
    stdin, stdout, stderr = client.exec_command(f'if ! test -f {rc_local_path}; then sudo touch {rc_local_path}; echo "#!/bin/sh -e" | sudo tee {rc_local_path}; echo "exit 0" | sudo tee -a {rc_local_path}; fi')
    errors = stderr.read().decode()
    if errors:
        log_text.insert('end', f'Error checking/creating /etc/rc.local: {errors}\n')
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
            log_text.insert('end', f'Error editing rc.local: {errors}\n')
            return

    # Change permissions of rc.local
    stdin, stdout, stderr = client.exec_command(f"sudo chmod +x {rc_local_path}")
    errors = stderr.read().decode()
    if errors:
        log_text.insert('end', f'Error changing permissions of rc.local: {errors}\n')
        return

    log_text.insert('end', 'Tunnel setup successful\n')


def setup_udpgw(client, log_text):
    # Ask the user for the UDPGW port
    udpgw_port = simpledialog.askinteger("UDPGW", "Please enter the UDPGW port:")

    # Download the file
    command = 'wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgw64"'
    stdin, stdout, stderr = client.exec_command(command)
    errors = stderr.read().decode()
    if "Saving to" not in errors:  # Check if a real error occurred
        log_text.insert('end', f'Error executing command "{command}": {errors}\n')
        return

    # Wait for the file to download
    time.sleep(8)

    # Create and edit the rc.local file
    rc_local_commands = [
        f"#!/bin/sh -e",
        f"screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:{udpgw_port}",
        f"exit 0",
    ]
    for command in rc_local_commands:
        stdin, stdout, stderr = client.exec_command(f'sudo bash -c "echo \'{command}\' >> /etc/rc.local"')
        errors = stderr.read().decode()
        if errors:
            log_text.insert('end', f'Error executing command "{command}": {errors}\n')
            return

    # Run the final command
    command = f"sudo chmod +x /etc/rc.local && sudo chmod +x /usr/bin/badvpn-udpgw && systemctl daemon-reload && sleep 0.5 && systemctl start rc-local.service && screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:{udpgw_port}"
    stdin, stdout, stderr = client.exec_command(command)
    errors = stderr.read().decode()
    if errors:
        log_text.insert('end', f'Error executing command "{command}": {errors}\n')
        return

    log_text.insert('end', 'UDPGW setup successful\n')



def main():
    # Create a Tk instance
    root = tk.Tk()
    root.title("C2C SSH V_1.07.12")

    # Select Vapor style for the app
    style = Style(theme="vapor")

    # Set the size of the main window
    root.geometry('980x500')

    # Create a frame of size 1420*1015 inside the main window
    app_frame = ttk.Frame(root, width=1420, height=1015, padding=15)
    app_frame.grid(sticky='nw') 

    # Create a frame of size 300*300 inside the app_frame
    login_frame = ttk.Frame(app_frame, width=300, height=300, padding=15)
    login_frame.grid(row=0, column=0, sticky='nw') 

    # Create labels and inputs inside the login_frame
    labels = [
        'IP or Domain:',
        'Server Port:',
        'Username:',
        'Password:',
    ]
    inputs = []
    for i, text in enumerate(labels):
        label = ttk.Label(login_frame, text=text)
        label.grid(row=i, column=0, sticky='e', padx=5, pady=5)
        input = ttk.Entry(login_frame, width=20)
        input.grid(row=i, column=1, padx=5, pady=5)
        inputs.append(input)

    # Create a connect button inside the login_frame
    connect_button = ttk.Button(
        login_frame,
        text='Connect to Server',
        command=lambda: connect_to_server(
            inputs[0].get(),
            inputs[1].get(),
            inputs[2].get(),
            inputs[3].get(),
            log_text,
        )
    )
    connect_button.grid(row=i+2, column=1, columnspan=2, padx=10, pady=10)

    # Create another frame of size 950*475 inside the app_frame
    tab_frame = ttk.Frame(app_frame, width=950, height=475, padding=15)
    tab_frame.grid(row=0, column=1, sticky='ne') 

    # Create a Notebook (tabbed widget) inside the tab_frame
    tabs = ttk.Notebook(tab_frame)

    # Create 7 tabs
    tab_names = [
        'Server Monitoring',
        'Server Security',
        'User Management',
        'Server Management',
        'Install Website',
        'Install Panel',
        'Proxy',
    ]

    buttons_in_install_website = [
        'Install Nginx',
        'Upload Web Site',
        'Install Certbot',
        'Get SSL Certificate',
    ]

    buttons_in_server_management = [
        
    ]

    buttons_in_install_panel_column1 = [
        'X-UI Orginall',
        'Alireza',
        'MHSanaei',
        'Kafka',
        'Vaxilu',
    ]

    buttons_in_install_panel_column2 = [
        'Hiddify',
        'Dragon',
        'X Panel',
    ]

    for name in tab_names:
        tab = ttk.Frame(tabs)  
        if name == 'User Management':
            add_user_button = ttk.Button(tab, text='Add user', width=20, command=lambda: add_user(client, log_text)) 
            add_user_button.grid(row=0, column=0, padx=5, pady=5, sticky='w')
            delete_user_button = ttk.Button(tab, text='Delete user', width=20, command=lambda: delete_user(client, log_text)) 
            delete_user_button.grid(row=1, column=0, padx=5, pady=5, sticky='w')
            change_password_button = ttk.Button(tab, text='Change user password', width=20, command=lambda: change_user_password(client, log_text)) 
            change_password_button.grid(row=2, column=0, padx=5, pady=5, sticky='w')
            list_users_button = ttk.Button(tab, text='List of users', width=20, command=lambda: list_users(client, log_text, root)) 
            list_users_button.grid(row=3, column=0, padx=5, pady=5, sticky='w')

        elif name == 'Server Security':
            change_ssh_port_button = ttk.Button(tab, text='Change SSH Port', width=20, command=lambda: change_ssh_port(client, log_text))
            change_ssh_port_button.grid(row=0, column=0, padx=5, pady=5, sticky='w')

            # rest of buttons...
        elif name == 'Install Website':
            for i, btn_name in enumerate(buttons_in_install_website):
                button = ttk.Button(tab, text=btn_name, width=20) 
                button.grid(row=i, column=0, padx=5, pady=5, sticky='w')
        elif name == 'Proxy':
            button = ttk.Button(tab, text='Start Proxy', width=20) 
            button.grid(row=0, column=0, padx=5, pady=5, sticky='w')
        elif name == 'Server Management':
            for i, btn_name in enumerate(buttons_in_server_management):
                button = ttk.Button(tab, text=btn_name, width=20) 
                button.grid(row=i, column=0, padx=5, pady=5, sticky='w')

            tunnel_setup_button = ttk.Button(tab, text='Tunnel Setup', width=20, command=lambda: tunnel_setup(client, log_text))
            tunnel_setup_button.grid(row=i+1, column=0, padx=5, pady=5, sticky='w')
            udpgw_button = ttk.Button(tab, text='UDPGW', width=20, command=lambda: setup_udpgw(client, log_text))
            udpgw_button.grid(row=0, column=0, padx=5, pady=5, sticky='w')
        
        elif name == 'Install Panel':
            for i, btn_name in enumerate(buttons_in_install_panel_column1):
                button = ttk.Button(tab, text=btn_name, width=20) 
                button.grid(row=i, column=0, padx=5, pady=5, sticky='w')
            for i, btn_name in enumerate(buttons_in_install_panel_column2):
                button = ttk.Button(tab, text=btn_name, width=20) 
                button.grid(row=i, column=1, padx=5, pady=5, sticky='w')
        elif name == 'Server Monitoring':

            # Create a label for the CPU Progressbar
            cpu_label = ttk.Label(tab, text='CPU Usage:')
            cpu_label.grid(row=0, column=0, pady=5) 

            # Create the first Progressbar widget
            cpu_progress = ttk.Progressbar(
                tab,
                length=200,
                mode='determinate',
                style='striped.Horizontal.TProgressbar'
            )
            cpu_progress.grid(row=1, column=0, pady=5)  # Add some padding in y-direction for visual clarity

            # Create a label for the RAM Progressbar
            ram_label = ttk.Label(tab, text='RAM Usage:')
            ram_label.grid(row=2, column=0, pady=5)

            # Create the second Progressbar widget
            ram_progress = ttk.Progressbar(
                tab,
                length=200,
                mode='determinate',
                style='danger-striped.Horizontal.TProgressbar'
            )
            ram_progress.grid(row=3, column=0, pady=5)  # This one goes below the first one


            # Create the first IP Entry
            ip4_entry = ttk.Entry(tab, width=20)
            ip4_entry.insert(0, 'Default IP4')  # Set a default value
            ip4_entry.grid(row=1, column=2, padx=5, pady=5)

            # Create the second IP Entry
            ip6_entry = ttk.Entry(tab, width=20)
            ip6_entry.insert(0, 'Default IP6')  # Set a default value
            ip6_entry.grid(row=3, column=2, padx=5, pady=5)

            # Connect to server and start updating server info
            client = None

            def connect_and_update():
                nonlocal client
                client = connect_to_server(
                    inputs[0].get(),
                    inputs[1].get(),
                    inputs[2].get(),
                    inputs[3].get(),
                    log_text
                )

                if client:
                    threading.Thread(
                        target=update_server_info,
                        args=(client, cpu_progress, ram_progress, ip4_entry, ip6_entry),
                        daemon=True
                    ).start()

            connect_button.config(command=connect_and_update)


        tabs.add(tab, text=name)  

    tabs.pack(expand=True, fill='both')

    # Creating log frame at the bottom of the app_frame
    log_frame = ttk.Frame(app_frame, width=1400, height=200, padding=15)
    log_frame.grid(row=1, column=0, columnspan=2, sticky='sw')

    # Adding a Text widget to display logs
    log_text = tk.Text(log_frame, width=130, height=10)
    log_text.pack(side="left", fill="y")

    # Adding a Scrollbar to the Text widget
    scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=log_text.yview)
    scrollbar.pack(side="right", fill="y")

    # Configuring the text widget to work with the scrollbar
    log_text.configure(yscrollcommand=scrollbar.set)

    root.mainloop()

if __name__ == '__main__':
    main()
