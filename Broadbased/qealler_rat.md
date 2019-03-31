# Qealler

## Write-Up & Reporting
* https://github.com/jeFF0Falltrades/Malware-Writeups/tree/master/Qealler
* https://www.cyberark.com/threat-research-blog/qealler-the-silent-java-credential-thief/

## Sample Hashes
```
Remittance_Advice.jar
8d564a18b902461c19936ccb1f4e2f12
72de1a2ca8ff223f72efb366e64ed480c89f1d58
3724d27b119d74c04c7860a1fc832139ea714ef4b8723bc1b84a6b166b967405
3072:to8ZlTq4dPEXAJP3X+4ZPxEHVwHEWAakaEra9Iqv+ZA:KclW4d8QJP3X3PO1UAak9ra9HsA

7z.jar
a593cb286e0fca1ca62e690022c6d918
227f06265c5e44ef32647bb933d62fffea2a972c
93b6a8ecb84fe9771584c329d47ff109464d2ff65c88917d7acff75c5ddd0912
12288:uiI0fU+gNrDCc8tE5KU955GuZ8YhbbF0q+2jOsOVvetYB2K0iPkm+AVkX:NLoBcEkmMu6kbcsAvFH0iPkmhVE

qealler.7z
8d2c718599ed0aff7ab911e3f1966e8c
a64525f26076821ac07c4078ca5664ce2cf2c313
a31497597cd9419dde7fc724b7e25a465f7d95ff7bd52cf3be59928499983608
24576:Fvv7N1Xm3LCGMi2h3V8BCRSRuMgwHeI7yc71l5i+W/NBu1v03ev/hqvcxSk7rw2e:FLryCni2YBqdgeKYlBm0OhU
cKdh3p

main.py
5a8915c3ee5307df770abdc109e35083
e4fd1685ad7df5e09c12d6330621b3aaf81206d2
9992dd2941df8dcd3448d80d6bab8dfa57356ff44fbe840e830fe299d18a9031
3072:kpVOVg8ZucPfYNycK7KfZEFRlg95VpaQY3QvFd:OvaiZE2RL
```

## Sample C2
```
http[:]//lunogroup.co[.]uk/Remittance_Advice.jar
http[:]//146[.]185.139.123:6289/qealler-reloaded/ping
http[:]//146[.]185.139.123:6521/lib/qealler
http[:]//139[.]59.76.44:4000/lib/7z
http[:]//139[.]59.76.44:4000/lib/qealler
http[:]//139[.]59.76.44:4000/qealler-reloaded/ping
```
