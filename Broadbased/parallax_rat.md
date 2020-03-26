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
