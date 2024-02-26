# SSH Packet Spoofer

This utility allows you to spoof SSH packets as HTTP packets, by adding the HTTP header on top of the transmitted packets.

Consists of 2 units launched from the same binary: spoofer and despoofer

Spoofer will allow real clients to conntect to the spoofer, and will spoof and forward the packets to the despoofer.
Despoofer will receive the packets to the real server residing preferably, in the same computer through localhost.
