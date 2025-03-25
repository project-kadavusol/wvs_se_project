#!/bin/bash

# Function to check if cloudflared is installed
check_cloudflared() {
    if ! command -v cloudflared &> /dev/null; then
        echo "Cloudflare Tunnel not found. Installing..."
        wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -O cloudflared
        chmod +x cloudflared
        echo "Installation complete."
    fi
}

# Function to get valid IP address input
get_ip() {
    while true; do
        read -p "Please enter the IP address: " ip
        if [[ -n "$ip" ]]; then
            break
        else
            echo "IP address cannot be empty. Please try again."
        fi
    done
}

# Function to get valid port input
get_port() {
    while true; do
        read -p "Please enter the port number: " port
        if [[ -n "$port" ]]; then
            break
        else
            echo "Port number cannot be empty. Please try again."
        fi
    done
}

# Main script execution
check_cloudflared
get_ip
get_port

echo "Starting Cloudflare Tunnel..."
./cloudflared tunnel --url http://$ip:$port &
echo "Cloudflare Tunnel started. Copy the generated URL and paste it into the scanner."
wait
