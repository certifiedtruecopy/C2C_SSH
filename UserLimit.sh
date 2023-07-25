#!/bin/bash

users=()
max_conns=()
block_minutes=10

while IFS=, read -r user max_conn; do
    users+=("$user")
    max_conns+=("$max_conn")
done < /var/log/users.csv

while true; do
    for index in ${!users[*]}; do
        user=${users[$index]}
        max_connections=${max_conns[$index]}
        
        user_ip=$(grep 'sshd.*Accepted' /var/log/auth.log | grep "$user" | awk '{print $11}' | tail -n1)
        
        connections=$(ps aux | grep "sshd: $user" | awk '!/priv/' | grep -v grep | wc -l)

        echo "Connections: $connections" 
        echo "Max connections: $max_connections" 

        if (( connections > max_connections )); then
            echo "$user has too many connections ($connections), blocking for $block_minutes minutes"
            iptables -I INPUT -p tcp --dport 22 -s $user_ip -j REJECT
            
            sleep $((block_minutes * 60))
            
            iptables -D INPUT -p tcp --dport 22 -s $user_ip -j REJECT
        fi
    done
    sleep 60
done
