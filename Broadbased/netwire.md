# Netwire RAT

## Reporting
* https://www.cyber.nj.gov/threat-profiles/trojan-variants/netwire-rat
* https://unit42.paloaltonetworks.com/new-release-decrypting-netwire-c2-traffic/

## YARA
```yara
rule netwire {
  meta:
    author = "jeFF0Falltrades"
    hash = "80214c506a6c1fd8b8cd2cd80f8abddf6b771a4b5808a06636b6264338945a7d"

  strings:
    $ping = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1" wide ascii nocase
    $bat_1 = "DEL /s \"%s\" >nul 2>&1" wide ascii nocase
    $bat_2 = "call :deleteSelf&exit /b" wide ascii nocase
    $bat_3 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b" wide ascii nocase
    $ua = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" wide ascii nocase
    $log = "[Log Started]" wide ascii nocase
    $xor = { 0F B6 00 83 F0 ?? 83 C0 ?? 88 02 } // movzx eax, byte ptr [eax]; xor eax, ??; add  eax, ??;  mov [edx], al (XOR encryption of log data)

  condition:
    4 of them
}
```

## Sample Hashes
```
a4e8949b2b8e541616d25dcbf9e9d15ba44ceda06bf601706dccbb0aa2f0091e
c8a0dd1af3b7f58f2342bb6eeafd0cc66e3af95bd7392ee5e9ee75d9b5abc0c5
a4e8949b2b8e541616d25dcbf9e9d15ba44ceda06bf601706dccbb0aa2f0091e
c8a0dd1af3b7f58f2342bb6eeafd0cc66e3af95bd7392ee5e9ee75d9b5abc0c5
bc49d96cdf17120a02d0e820aeae9797e0bbb0ab4b4904a01922e0a1bd39caee
bc49d96cdf17120a02d0e820aeae9797e0bbb0ab4b4904a01922e0a1bd39caee
777b89daf016d92dba7e4ae024e3a16c69ea795e7a74a910ff5e807fabe6dbb3
777b89daf016d92dba7e4ae024e3a16c69ea795e7a74a910ff5e807fabe6dbb3
c1bab10eb2f2934354eac8c2a2c431426c649c942cab1e4275fe280efd6def9f
c1bab10eb2f2934354eac8c2a2c431426c649c942cab1e4275fe280efd6def9f
54e4c8e9d697055b4be27296d895e79ee88d46194a1b2c3b2185e7e6713ff6ed
04a66d23bad9f2bf66c5e57870574017d5ca24346d4010d450ce2727b4af91f8
fbcba00060ac9a4df0865a25bfc47945f4f71d467287c92507f70005ef50b07d
fbcba00060ac9a4df0865a25bfc47945f4f71d467287c92507f70005ef50b07d
8f27a9e704a311496dbd143c5ca5502c4be2676c3c88b46711370f276f57c18f
```
