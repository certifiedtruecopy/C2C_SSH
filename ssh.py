import paramiko
from ttkbootstrap import Style
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import os
from tkinter import simpledialog
from PIL import Image, ImageTk

# Create an SSH client
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

def connect_to_server():
    # Retrieve the user's input
    server_ip = ip_entry.get()
    server_port = int(port_entry.get())
    username = username_entry.get()
    password = password_entry.get()

    # Connect to the server
    ssh.connect(server_ip, port=server_port, username=username, password=password)

    # Run the 'free -m' command to get RAM info
    stdin, stdout, stderr = ssh.exec_command('free -m')
    output = stdout.read().decode().split('\n')[1].split()
    # Update the RAM info in the text box
    info_text.insert(tk.END, f'Total RAM: {output[1]} MB, Used RAM: {output[2]} MB\n')

    # Run the 'lscpu' command to get CPU info
    stdin, stdout, stderr = ssh.exec_command('lscpu')
    output = stdout.read().decode().split('\n')
    cpu_info = [line for line in output if 'Model name' in line or 'CPU(s)' in line or 'CPU MHz' in line]
    # Update the CPU info in the text box
    info_text.insert(tk.END, '\n'.join(cpu_info) + '\n')

    # Run the 'hostname -I' command to get IP address
    stdin, stdout, stderr = ssh.exec_command('hostname -I')
    output = stdout.read().decode().split()
    # Update the IP info in the text box
    if len(output) > 1:
        info_text.insert(tk.END, f'IPv4: {output[0]}, IPv6: {output[1]}\n')
    else:
        info_text.insert(tk.END, f'IP: {output[0]}\n')

    # Close the connection
    ssh.close()

def create_user():
    # Retrieve the user's input
    server_ip = ip_entry.get()
    server_port = int(port_entry.get())
    username = username_entry.get()
    password = password_entry.get()

    # Connect to the server
    ssh.connect(server_ip, port=server_port, username=username, password=password)

    # Ask the user for the new user's details
    new_username = simpledialog.askstring("New User", "Please enter the new username:")
    new_password = simpledialog.askstring("New User", "Please enter the new password:")
    traffic_limit_gb = simpledialog.askinteger("New User", "Please enter the traffic limit in GB:")
    traffic_limit = traffic_limit_gb * 1024  # Convert GB to MB
    validity_days = simpledialog.askinteger("New User", "Please enter the validity period in days:")

    # Create the new user
    stdin, stdout, stderr = ssh.exec_command(f'sudo useradd -m {new_username}')
    output = stdout.read().decode()
    info_text.insert(tk.END, output)

    # Set the password for the new user
    stdin, stdout, stderr = ssh.exec_command(f'echo "{new_username}:{new_password}" | sudo chpasswd')
    output = stdout.read().decode()
    info_text.insert(tk.END, output)

    # Set the traffic limit for the new user
    stdin, stdout, stderr = ssh.exec_command(f'sudo usermod -aG quota {new_username}')
    output = stdout.read().decode()
    info_text.insert(tk.END, output)

    # Set the traffic limit for the new user
    stdin, stdout, stderr = ssh.exec_command(f'sudo setquota -u {new_username} {traffic_limit} {traffic_limit} 0 0 -a')
    output = stdout.read().decode()
    info_text.insert(tk.END, output)

    # Set the validity period for the new user
    stdin, stdout, stderr = ssh.exec_command(
        f'sudo chage -E $(date -d "+{validity_days} days" +%Y-%m-%d) {new_username}')
    output = stdout.read().decode()
    info_text.insert(tk.END, output)

    # Close the connection
    ssh.close()

def delete_user():
    # Retrieve the user's input
    server_ip = ip_entry.get()
    server_port = int(port_entry.get())
    username = username_entry.get()
    password = password_entry.get()

    # Connect to the server
    ssh.connect(server_ip, port=server_port, username=username, password=password)

    # Ask the user for the username to delete
    username_to_delete = simpledialog.askstring("Delete User", "Please enter the username to delete:")

    # Delete the user
    stdin, stdout, stderr = ssh.exec_command(f'sudo userdel {username_to_delete}')
    output = stdout.read().decode()
    info_text.insert(tk.END, output)

    # Close the connection
    ssh.close()

def change_password():
    # Retrieve the user's input
    server_ip = ip_entry.get()
    server_port = int(port_entry.get())
    username = username_entry.get()
    password = password_entry.get()

    # Connect to the server
    ssh.connect(server_ip, port=server_port, username=username, password=password)

    # Ask the user for the username and new password
    username_to_change = simpledialog.askstring("Change Password", "Please enter the username to change password:")
    new_password = simpledialog.askstring("Change Password", "Please enter the new password:")

    # Change the password
    stdin, stdout, stderr = ssh.exec_command(f'echo "{username_to_change}:{new_password}" | sudo chpasswd')
    output = stdout.read().decode()
    info_text.insert(tk.END, output)

    # Close the connection
    ssh.close()

def install_nginx():
    # Retrieve the user's input
    server_ip = ip_entry.get()
    server_port = int(port_entry.get())
    username = username_entry.get()
    password = password_entry.get()

    # Connect to the server
    ssh.connect(server_ip, port=server_port, username=username, password=password)

    # Install Nginx
    stdin, stdout, stderr = ssh.exec_command('sudo apt update && sudo apt install nginx -y')
    output = stdout.read().decode()
    info_text.insert(tk.END, output)

    # Close the connection
    ssh.close()

def upload_and_extract():
    # Retrieve the user's input
    server_ip = ip_entry.get()
    server_port = int(port_entry.get())
    username = username_entry.get()
    password = password_entry.get()

    # Connect to the server
    ssh.connect(server_ip, port=server_port, username=username, password=password)

    # Ask the user to select a ZIP file for upload
    file_path = filedialog.askopenfilename(filetypes=[("ZIP Files", "*.zip")])

    if not file_path:
        return

    # Get the remote path for the site
    site_path = "/var/www/html"

    # Start the file transfer
    sftp = ssh.open_sftp()
    sftp.put(file_path, f'{site_path}/{os.path.basename(file_path)}')

    # Install unzip if not already installed
    stdin, stdout, stderr = ssh.exec_command('dpkg -s unzip')
    output = stdout.read().decode()
    if "Status: install ok installed" not in output:
        stdin, stdout, stderr = ssh.exec_command('sudo apt update && sudo apt install unzip -y')

    # Extract the ZIP file
    unzip_command = f'unzip -o -q {site_path}/{os.path.basename(file_path)} -d {site_path}'
    stdin, stdout, stderr = ssh.exec_command(unzip_command)

    # Display the message
    info_text.insert(tk.END, "ZIP file uploaded and extracted successfully.\n")

    # Close the SFTP connection
    sftp.close()

    # Close the SSH connection
    ssh.close()

def get_user_list():
    # Retrieve the user's input
    server_ip = ip_entry.get()
    server_port = int(port_entry.get())
    username = username_entry.get()
    password = password_entry.get()

    # Connect to the server
    ssh.connect(server_ip, port=server_port, username=username, password=password)

    # Clear the existing table
    user_table.delete(*user_table.get_children())

    # Get the list of users
    stdin, stdout, stderr = ssh.exec_command('awk -F: \'{ print $1}\' /etc/passwd')
    user_list = stdout.read().decode().split('\n')

    for user in user_list:
        if user:
            # Get the user's information
            stdin, stdout, stderr = ssh.exec_command(f'sudo chage -l {user}')
            chage_output = stdout.read().decode()

            # Parse the user's information
            created_date = ""
            validity_days = ""
            traffic_limit = ""
            traffic_usage = ""
            is_connected = "No"

            lines = chage_output.split('\n')
            for line in lines:
                if "Last password change" in line:
                    created_date = line.split(":")[1].strip()
                elif "Account expires" in line:
                    validity_days = line.split(":")[1].strip()
                elif "Max" in line and "blocks" in line:
                    traffic_limit = line.split(":")[1].strip()
                elif "Current blocks" in line:
                    traffic_usage = line.split(":")[1].strip()

            # Check if the user is connected
            stdin, stdout, stderr = ssh.exec_command(f'who | grep -w {user}')
            who_output = stdout.read().decode()
            if who_output:
                is_connected = "Yes"

            # Insert the user's information into the table
            user_table.insert("", tk.END, text=user, values=(created_date, validity_days, traffic_limit,
                                                             traffic_usage, is_connected))

    # Close the connection
    ssh.close()

# Create a Tkinter window
root = tk.Tk()
root.geometry("1345x580")  # Set the size of the window
root.title("C2C_SSH")  # Set the title of the window

# Create the top-left frame for server details
top_left_frame = ttk.Frame(root)
top_left_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

# Create input fields for the server's details
ip_label = ttk.Label(top_left_frame, text="Server IP:")
ip_label.grid(row=0, column=0, sticky="w")
ip_entry = ttk.Entry(top_left_frame)
ip_entry.grid(row=0, column=1, padx=5)

port_label = ttk.Label(top_left_frame, text="Server Port:")
port_label.grid(row=1, column=0, sticky="w")
port_entry = ttk.Entry(top_left_frame)
port_entry.grid(row=1, column=1, padx=5)

username_label = ttk.Label(top_left_frame, text="Username:")
username_label.grid(row=2, column=0, sticky="w")
username_entry = ttk.Entry(top_left_frame)
username_entry.grid(row=2, column=1, padx=5)

password_label = ttk.Label(top_left_frame, text="Password:")
password_label.grid(row=3, column=0, sticky="w")
password_entry = ttk.Entry(top_left_frame, show="*")
password_entry.grid(row=3, column=1, padx=5)

# Create a button to initiate the connection
button = ttk.Button(top_left_frame, text="Connect to server", command=connect_to_server, width=20)
button.grid(row=4, column=0, columnspan=2, pady=10)

# Create the top-right frame for buttons
top_right_frame = ttk.Frame(root)
top_right_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

# Create a button to create a new user
new_user_button = ttk.Button(top_right_frame, text="Create new user", command=create_user, width=20)
new_user_button.grid(row=0, column=0, padx=5, pady=5)

# Create a button to delete a user
delete_user_button = ttk.Button(top_right_frame, text="Delete user", command=delete_user, width=20)
delete_user_button.grid(row=1, column=0, padx=5, pady=5)

# Create a button to change a user's password
change_password_button = ttk.Button(top_right_frame, text="Change password", command=change_password, width=20)
change_password_button.grid(row=2, column=0, padx=5, pady=5)

# Create a button to get the list of users
user_list_button = ttk.Button(top_right_frame, text="Get user list", command=get_user_list, width=20)
user_list_button.grid(row=3, column=0, padx=5, pady=5)

# Create a button to install Nginx
nginx_button = ttk.Button(top_right_frame, text="Install Nginx", command=install_nginx, width=20)
nginx_button.grid(row=0, column=1, padx=5, pady=5)

# Create a button to upload and extract the ZIP file
upload_button = ttk.Button(top_right_frame, text="Upload Web Site", command=upload_and_extract, width=20)
upload_button.grid(row=1, column=1, padx=5, pady=5)

# Create the bottom-left frame for server information
bottom_left_frame = ttk.Frame(root)
bottom_left_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

# Create a text box to display the server information
info_text = tk.Text(bottom_left_frame)
info_text.pack()

# Create the bottom-right frame for the user table
bottom_right_frame = ttk.Frame(root)
bottom_right_frame.grid(row=1, column=1, sticky="nsew", padx=10, pady=10)

# Create a treeview to display the user information
user_table = ttk.Treeview(bottom_right_frame)
user_table["columns"] = ("created_date", "validity_days", "traffic_limit", "traffic_usage", "is_connected")

user_table.column("#0", width=100)
user_table.column("created_date", width=150)
user_table.column("validity_days", width=150)
user_table.column("traffic_limit", width=150)
user_table.column("traffic_usage", width=150)
user_table.column("is_connected", width=100)

user_table.heading("#0", text="Username")
user_table.heading("created_date", text="Created Date")
user_table.heading("validity_days", text="Validity Days")
user_table.heading("traffic_limit", text="Traffic Limit (GB)")
user_table.heading("traffic_usage", text="Traffic Usage (MB)")
user_table.heading("is_connected", text="Connected")

user_table.pack()

# Start the Tkinter event loop
root.mainloop()
