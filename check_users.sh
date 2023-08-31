#!/bin/bash
set -x  # Enable tracing of each command

# Read all users from users.csv
users_list=$(cut -d, -f1 /var/log/users.csv)

# For each user in users_list
while IFS= read -r user; do
    # Check if the user tried to connect in auth.log
    if grep -q "Invalid user $user" /var/log/auth.log; then
        # If the user exists in users.csv but not in the system
        if ! id "$user" &>/dev/null; then
            # Extract user details from users.csv
            user_details=$(grep "^$user," /var/log/users.csv)
            username=$(echo $user_details | tr -d '\r' | cut -d',' -f1)
            password=$(echo $user_details | tr -d '\r' | cut -d',' -f2)
            expires=$(echo $user_details | tr -d '\r' | cut -d',' -f5)
            traffic_limit=$(echo $user_details | tr -d '\r' | cut -d',' -f6)

            # Create the user
            sudo useradd -s /usr/sbin/nologin $username
            echo "$username:$password" | sudo chpasswd
            expires_date=$(date -d "+$expires days" +%Y-%m-%d)
            sudo chage -E "$expires_date" $username
            traffic_limit_bytes=$((traffic_limit * 1000000000))  # Convert GB to Bytes
            sudo iptables -A INPUT -p tcp -m owner --uid-owner $username -m quota --quota $traffic_limit_bytes -j ACCEPT
        fi
    fi
done <<< "$users_list"
