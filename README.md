
# GoVPN — Custom Linux VPN in Go

## What is this

A from-scratch VPN implementation for Linux written in Go. Custom protocol built on raw sockets and a TUN interface. Developed and tested in a **private LAN / local VM environment**.

---

## Current Architecture

### Handshake & Auth (TCP :9000)
- Client and server exchange X25519 ECDH public keys
- Both sides HMAC the public key with a **pre-shared key** to authenticate each other
- Shared secret is derived → SHA256 hashed into a per-session AES-256-GCM key
- Server assigns a VPN IP (`192.168.0.x`) and a random 16-bit session ID, encrypts and sends it back

### Data Plane (UDP :51820)
- Client reads plaintext packets from TUN, encrypts with AES-256-GCM, wraps in a custom tagged payload and sends to server
- Server receives, strips the tag, decrypts, writes to TUN (and vice versa)
- Custom packet format:
```
[vpnIpEnd 1B][sequence idx 8B][AES-GCM encrypted IP packet]
```
- Replay protection via a 64-bit sliding window bitmask

### Session Management
- Server maintains a session map keyed by `vpnIpEnd` byte
- Each session tracks: real NIC IP, VPN IP, encryption handler, traffic bytes, sequence counters
- IP pool assigns `192.168.0.10` – `192.168.0.240`

### Heartbeat (TCP :9001)
- Server initiates HB to client every 20 seconds
- HMAC signed with directional labels (`server->client`, `client->server`)
- Replay protected by timestamp (10s window)
- Session killed after 60s of no valid HB response
- Session also killed after 2m of no traffic on a session

---

## Current Mode: Private LAN / Local VM Only

The data plane uses a **hand-crafted raw IP+UDP header** with a static source IP passed via `--nic` flag. This works correctly in a controlled local environment where the source IP is reachable. It **does not work** when the client is behind NAT (e.g. home router → GCloud server) because the crafted source IP is a private address the server cannot route back to.

---

## Improvements

### Critical

| Issue | Description |
|---|---|
| **NAT incompatibility** | Client builds raw IP packet with `--nic` (private LAN IP) as source. Behind NAT the server saves this unreachable IP and all return traffic is lost. Fix: client send path should use `SOCK_DGRAM` and let the kernel fill the correct source IP. |
| **Heartbeat direction** | Server initiates TCP dial to client on port 9001. Behind NAT inbound TCP connections are blocked by the router. Fix: flip direction — client initiates, server responds. |
| **Hard-coded pre-shared key** | `preSharedKey = "asd123"` is in plaintext in source. Must be loaded from config file or environment variable. |

### Security

| Issue | Description |
|---|---|
| **No forward secrecy rotation** | Session key is derived once at handshake and never rotated. Long-lived sessions are vulnerable if the key is ever exposed. |
| **Session ID is only 16-bit** | Collision probability is non-trivial with many sessions. Expand to 32-bit minimum. |
| **No certificate / PKI** | Authentication relies solely on a pre-shared key.|

### Reliability

| Issue | Description |
|---|---|
| **MTU hardcoded to 1400** | Auto-detected based on path MTU. |
| **No reconnect logic on client** | If session drops, client has no mechanism to re-authenticate automatically. |
| **IP pool limit** | Max 230 concurrent clients (`10`–`240`). |

