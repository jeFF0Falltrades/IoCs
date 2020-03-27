# Parallax RAT

## Reporting
* https://twitter.com/VK_Intel/status/1238191501429084160
* https://malpedia.caad.fkie.fraunhofer.de/details/win.parallax

## YARA
```yara
rule parallax_rat_2020 {
  meta:
    author = "jeFF0Falltrades"
    
  strings:
    $str_ws = ".DeleteFile(Wscript.ScriptFullName)" wide ascii
    $str_cb_1 = "Clipboard Start" wide ascii
    $str_cb_2 = "Clipboard End" wide ascii
    $str_un = "UN.vbs" wide ascii
    $hex_keylogger = { 64 24 ?? C0 CA FA }

  condition:
    3 of them
}
```

## Sample Hashes
```
9259cb359a7e5a9581549c6500f3c764fb6f5ff2907b50fa90b9719e0a052a28
829FCE14AC8B9AD293076C16A1750502C6B303123C9BD0FB17C1772330577D65
d90f7987cd63d82a0e4709c4b16a991f2a583227cee26d0c1329245bfd912947
c56432c5453252d948c314408e5a5beba0dbeeaa0b20733095e69dfe3866e063
```

## Keylogger Decryption
The hex string in the YARA rule above is a snippet of the algorithm used to encrypt the keylogging file for recent Parallax RAT samples.

The same sequence of bitwise operations is often used to encrypt the keylogging output file, though these operations do not always appear sequentially in the payload:

```
LD dl, <byte of keylogging stream>
XOR dl, 50
XOR dl, DC
ADD dl, EA
SUB dl, 41
ROR dl, FA
ADD dl, 53
```

The following simple Python script can be used to decrypt keylogging output files encrypted with this algorithm:

```python
MAX_BITS = 8


def rol(val, r_bits, MAX_BITS):
    return (val << r_bits%MAX_BITS) & (2**MAX_BITS-1) | \
    ((val & (2**MAX_BITS-1)) >> (MAX_BITS-(r_bits%MAX_BITS)))


def decode(b):
    b = (b - 0x53) & 0xFF
    b = rol(b, 0xFA, MAX_BITS)
    b = (b + 0x41) & 0xFF
    b = (b - 0xEA) & 0xFF
    b = (b ^ 0xDC) & 0xFF
    b = (b ^ 0x50) & 0xFF
    return b


c = []
with open('kl.bin', 'rb') as f:
    data = f.read()
for d in data:
    c.append(chr(decode(d)))
print(''.join(c))
```

**Sample Output**
```
Clipboard Start
C:\Users\victim\AppData\Roaming\Data
Clipboard End
[F2][F2][F9][Ctrl][Ctrl + G]
3/27/2020__5:32:59 AM 
Clipboard Start
Stop keylogging me
Clipboard End
[Enter][Shift]
```
