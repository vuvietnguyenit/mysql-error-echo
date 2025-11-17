# mysql-error-echo

Observability tool that traces and inspects MySQL server error responses directly use **packet sniffing**, without modifying or instrumenting client applications. It capture packets sent from the MySQL server to clients and inspects them on-the-fly only for error responses.
From there, we can see all of error responses in just one place, that is very helpful if we have too many backends/clients are connecting to server.

**This tool we can use to work with mysqlrouter/mysql/mariadb**

**Note: It only supports unencrypted MySQL traffic (when ssl-mode=DISABLE).**

## How It Works

### Logical architecture diagram

```mermaid
flowchart LR
    A[We got a packet] -->|filter source port| B{Is mysql port ?}
    B -->|True| D{0xFF in 
        bytestream ?}
    B -->|False| E[skip]
    D -->|True| F[decode message 
        and show it ]
    D -->|False| E

```

## Usage

```bash
# ./mysql-error-echo -h
Usage of ./mysql-error-echo:
  -cache-duration duration
        Duration to keep DNS cache entries (example: 30s, 5m, 1h) (default 5m0s)
  -cache-size int
        Maximum number of entries to store in DNS cache (default 4096)
  -iface string
        Network interface to capture/process packets on (default "eth0")
  -nameserver string
        Custom DNS nameserver to use (example: 8.8.8.8:53). Leave empty to use system resolver
  -port int
        MySQL server port to trace (default 3306)
  -use-dns
        Resolve IP to domain (enable DNS reverse lookup)
```

For example, if you want to sniff error responses from MySQL server (on port 3306) at ens3 interface that are being sent back to clients.

```bash
# ./mysql-error-echo -iface ens3 -port 3306
{"time":"2025-11-17T11:33:05.547757911+07:00","level":"INFO","msg":"listening for MySQL error packets on","iface":"ens3","port":3306}
```
Example results:
```json
{"time":"2025-11-17T04:16:35.570455851Z","level":"INFO","msg":"MySQL ERR packet","src_ip":"10.199.230.0","src_port":6446,"dst_ip":"10.194.60.90","dst_port":35976,"length":64,"error_message":"\ufffd\u0014\u0004#42000Access denied for user 'router'@'%' to database 'mysql'"}
{"time":"2025-11-17T04:16:33.225500267Z","level":"INFO","msg":"MySQL ERR packet","src_ip":"10.199.230.0","src_port":6446,"dst_ip":"10.194.60.90","dst_port":34650,"length":123,"error_message":"\ufffd\u0015\u0004#28000Access denied for user 'root'@'domain.svc.cluster.local' (using password: YES)"}
{"time":"2025-11-17T08:05:13.98333153Z","level":"INFO","msg":"MySQL ERR packet","src_ip":"10.199.230.42","src_port":6446,"dst_ip":"10.199.230.1","dst_port":52540,"length":145,"error_message":"\ufffd\ufffd\u000f#HY000The client was disconnected by the server because of inactivity. See wait_timeout and interactive_timeout for configuring this behavior."}
```


## Build
Require:
- Golang ver >= 1.25