#!/bin/bash

# Variables to store usernames and their max connections
declare -A user_maxconns
block_minutes=5

# Populate the associative array from users.csv
while IFS=, read -r username _ max_connections _ _ _; do
    # Skip the header line
    if [[ "$username" != "Username" ]]; then
        user_maxconns["$username"]=$max_connections
    fi
done < /var/log/users.csv

while true; do
    for user in "${!user_maxconns[@]}"; do
        max_connections=${user_maxconns["$user"]}
        
        user_ip=$(grep 'sshd.*Accepted' /var/log/auth.log | grep "$user" | awk '{print $11}' | tail -n1)
        
        connections=$(ps aux | grep "sshd: $user" | awk '!/priv/' | grep -v grep | wc -l)

        echo "Connections for $user: $connections" 
        echo "Max connections for $user: $max_connections" 

        if (( connections > max_connections )); then
            echo "$user has too many connections ($connections), blocking for $block_minutes minutes"
            iptables -I INPUT -p tcp --dport 22 -s $user_ip -j REJECT
            
            # Run the unblocking process in the background
            (
                sleep $((block_minutes * 60))
                iptables -D INPUT -p tcp --dport 22 -s $user_ip -j REJECT
            ) &
        fi
    done
    sleep 30
done
