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
    traffic_limit = traffic_limit_gb * 1024 # Convert GB to MB
    validity_days = simpledialog.askinteger("New User", "Please enter the validity period in days:")

    # Create the new user
    stdin, stdout, stderr = ssh.exec_command(f'sudo adduser {new_username} --gecos "" --disabled-password')
    output = stdout.read().decode()
    info_text.insert(tk.END, output)

    # Set the new user's password
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
    stdin, stdout, stderr = ssh.exec_command(f'sudo chage -E $(date -d "+{validity_days} days" +%Y-%m-%d) {new_username}')
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

    # Select the ZIP file to upload
    file_path = filedialog.askopenfilename()
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

    # Get the list of users
    stdin, stdout, stderr = ssh.exec_command('awk -F: \'{ print $1}\' /etc/passwd')
    user_list = stdout.read().decode().split('\n')

    # Update the user list in the text box
    info_text.insert(tk.END, '\n'.join(user_list))

    # Close the connection
    ssh.close()

# Create a Tkinter window
root = tk.Tk()
root.geometry("505x940") # Set the size of the window
root.title("C2C_SSH") # Set the title of the window

# Apply the Pulse style from ttkbootstrap
style = Style(theme='pulse')

# Create a frame to hold the IP image label
image_frame = tk.Frame(root)
image_frame.pack(side=tk.TOP, pady=10)

# Load and display the image
image = Image.open("icon.png")
image = image.resize((200, 200), Image.ANTIALIAS)
image = ImageTk.PhotoImage(image)
image_label = tk.Label(image_frame, image=image)
image_label.pack()

# Create input fields for the server's details
ip_label = ttk.Label(root, text="Server IP:")
ip_label.pack()
ip_entry = ttk.Entry(root)
ip_entry.pack()

port_label = ttk.Label(root, text="Server Port:")
port_label.pack()
port_entry = ttk.Entry(root)
port_entry.pack()

username_label = ttk.Label(root, text="Username:")
username_label.pack()
username_entry = ttk.Entry(root)
username_entry.pack()

password_label = ttk.Label(root, text="Password:")
password_label.pack()
password_entry = ttk.Entry(root, show="*")
password_entry.pack()

# Create a button to initiate the connection
button = ttk.Button(root, text="Connect to server", command=connect_to_server, width=20)
button.pack()

# Create a button to create the new user
new_user_button = ttk.Button(root, text="Create new user", command=create_user, width=20)
new_user_button.pack()

# Create a button to get the list of users
user_list_button = ttk.Button(root, text="Get user list", command=get_user_list, width=20)
user_list_button.pack()

# Create a button to install Nginx
nginx_button = ttk.Button(root, text="Install Nginx", command=install_nginx, width=20)
nginx_button.pack()

# Create a button to upload and extract the ZIP file
upload_button = ttk.Button(root, text="Upload Web Site", command=upload_and_extract, width=20)
upload_button.pack()

# Create a text box to display the info
info_text = tk.Text(root)
info_text.pack()

# Start the Tkinter event loop
root.mainloop()
