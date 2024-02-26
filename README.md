# SSH Packet Spoofer

This utility allows you to spoof SSH packets as HTTP packets, by adding the HTTP header on top of the transmitted packets.

It will help you connect ssh over networks with extremely restrictive firewalls and packaet sniffers blocking SSH connections and packets based on the packet type.

Consists of 2 units launched from the same binary: spoofer and despoofer.

Spoofer will allow real clients to conntect to the spoofer, and will spoof and forward the packets to the despoofer.
Despoofer will receive the packets to the real server residing preferably, in the same computer through localhost.

## Building instructions

Simply build with gcc using C standard:
```
gcc -Wall -Wextra -Wpedantic -o bin/spoofer main.c
```

Or build with DEBUG logging:
```
gcc -Wall -Wextra -Wpedantic -DDEBUG -o bin/spoofer_debug main.c
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
