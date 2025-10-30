# Quick Start Guide

Get the Stealth SOCKS5 Proxy up and running in 60 seconds!

## Step 1: Build (10 seconds)

### Linux/macOS
```bash
chmod +x build.sh
./build.sh
```

### Windows
```cmd
build.bat
```

## Step 2: Run (5 seconds)

### Default (Local only, port 1080)
```bash
# Linux
./s5proxy_linux

# Windows
s5proxy.exe
```

### Custom Port & Address
```bash
# Linux - Listen on all interfaces, port 9050
./s5proxy_linux -addr 0.0.0.0:9050

# Windows
s5proxy.exe -addr 0.0.0.0:9050
```

## Step 3: Test (10 seconds)

```bash
# Test with curl
curl -x socks5://127.0.0.1:1080 https://ifconfig.me

# Expected output: Your public IP address
```

## That's it! 🎉

Your stealth SOCKS5 proxy is now running.

---

## Common Use Cases

### 1. Local Development Proxy
```bash
./s5proxy_linux -addr 127.0.0.1:1080
```
Configure your browser or app to use SOCKS5 proxy at `127.0.0.1:1080`

### 2. Red Team Pivoting (Stealth Mode)
```bash
./s5proxy_linux -addr 0.0.0.0:8443 -auth -user pivot -pass [secure-password]
```
Then connect from your attack machine:
```bash
ssh -D 8080 -L 8080:localhost:8443 user@target
```

### 3. Debugging / Verbose Logging
```bash
./s5proxy_linux -addr 127.0.0.1:1080 -v
```
Watch all connections in real-time.

### 4. Maximum Performance (Disable Stealth)
```bash
./s5proxy_linux -addr 127.0.0.1:1080 -no-stealth
```
For high-bandwidth applications where timing obfuscation isn't needed.

---

## Browser Configuration

### Firefox
1. Settings → Network Settings → Manual proxy configuration
2. SOCKS Host: `127.0.0.1`
3. Port: `1080`
4. Select: SOCKS v5
5. Check: "Proxy DNS when using SOCKS v5"

### Chrome/Chromium
Launch with:
```bash
google-chrome --proxy-server="socks5://127.0.0.1:1080"
```

### System-wide (Linux)
Edit `/etc/environment`:
```
all_proxy="socks5://127.0.0.1:1080"
```

---

## Proxychains Integration

1. Edit `/etc/proxychains.conf`:
```
[ProxyList]
socks5 127.0.0.1 1080
```

2. Use with any command:
```bash
proxychains curl https://ifconfig.me
proxychains nmap -sT target.com
proxychains firefox
```

---

## SSH Dynamic Port Forwarding

Combine with SSH for encrypted tunneling:

```bash
# Start proxy on remote server
./s5proxy_linux -addr 127.0.0.1:1080

# From local machine, create SSH tunnel
ssh -D 9999 -N user@remote-server

# Now use local port 9999 as SOCKS5 proxy
curl -x socks5://127.0.0.1:9999 https://ifconfig.me
```

---

## Security Checklist

- [ ] Change default credentials if using `-auth`
- [ ] Use `127.0.0.1` for local-only access
- [ ] Add firewall rules for exposed proxies
- [ ] Enable authentication for internet-facing deployments
- [ ] Wrap in TLS tunnel (stunnel/SSH) for encrypted transport
- [ ] Monitor logs with `-v` during initial deployment
- [ ] Use non-standard ports to avoid automated scans

---

## Troubleshooting

### Proxy won't start
```bash
# Check if port is already in use
ss -tuln | grep 1080

# Try different port
./s5proxy_linux -addr 127.0.0.1:9999
```

### Connection refused
```bash
# Make sure proxy is running
ps aux | grep s5proxy

# Check firewall
sudo ufw status
sudo iptables -L
```

### Slow connections
```bash
# Disable stealth mode
./s5proxy_linux -no-stealth

# Increase buffer size
./s5proxy_linux -buffer 65536
```

### Authentication not working
Currently, no-auth mode is recommended. Authentication module has a known issue being investigated.

**Workaround**: Use SSH tunneling for authentication/encryption instead.

---

## Next Steps

- Read [README.md](README.md) for full documentation
- Check [TESTING.md](TESTING.md) for test results
- Review `s5_proxy.odin` source code
- Contribute improvements!

## Support

Found a bug? Have a feature request?
- File an issue on GitHub
- Review the original s5.go project
- Check Odin language docs at https://odin-lang.org/

---

**Happy Proxying! 🚀**
