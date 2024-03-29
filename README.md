# SSH Packet Spoofer

This utility allows you to spoof SSH packets as HTTP packets, by adding the HTTP header on top of the transmitted packets.

It will help you connect ssh over networks with extremely restrictive firewalls and packaet sniffers blocking SSH connections and packets based on the packet type.

Consists of 2 units launched from the same binary: spoofer and despoofer.

Spoofer will allow real clients to conntect to the spoofer, and will spoof and forward the packets to the despoofer.
Despoofer will receive the packets to the real server residing preferably, in the same computer through localhost.

### Spoofer architecture:

![image not found](./img/Architecture.png "Spoofer Architecture: Avoid SSH traffic using HTTP traffic")

## Building instructions

Simply build the binary with make:
```bash
make
```

Or build with DEBUG logging:
```bash
make debug
```

Remove any obsolete build stuff:
```bash
make clean
```

Also VSCode settings pre-defined for building and debugging

## Running instructions

After building the binary, copy it over to the client and server machines (preferably)
or at least to a machine behind the same firewall than the client is resided.

On the client machine/network, run the sender (spoofer) instance simply by:
```
./bin/spoofer <SPOOFER_HOST/IP=LOCALHOST> <SPOOFER_PORT=1234> <DESPOOFER_HOST/IP> <DESPOOFER_PORT> SPOOFER HTTP
```
On the server machine/network, run the receiver (despoofer) instance simply by:
```
./bin/spoofer <DESPOOFER_HOST/IP> <DESPOOFER_PORT> <REAL_SERVER_HOST/IP> <REAL_SERVER_PORT> DESPOOFER HTTP
```
Then, on the client machine, simply connect SSH through the spoofer:
```
ssh -p <SPOOFER_PORT> user@<SPOOFER_HOST/IP>
```
It should open the SSH connection normally.

For example spoofer on the same machine as client, despoofer in the same machine as the real server, exposed through public ip 8.7.6.5 port 8765:
Client side, client on the same host:
```
./bin/spoofer 127.0.0.1 9876 8.7.6.5 8765 SPOOFER HTTP
```
Server side, server on the same host:
```
./bin/spoofer 0.0.0.0 8765 127.0.0.1 22 SPOOFER HTTP
```
Connect:
```
ssh -p 9876 user@localhost
```

### Notes on hosting
Note that privileged ports 1-1023 requires sudo/root access to host the spoofer/despoofer on. Prefer higher ports.
If executing on an on-premises environment, you might need to open the ports required to expose the traffic to outside LAN.
