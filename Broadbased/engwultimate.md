# EngWUltimate (aka Eng Whiz or Engr Whizzy)

## Reporting
* https://twitter.com/malwareforme/status/875091677807079424

## YARA
```yara
rule EngWUltimate {
        meta:
                author = "jeFF0Falltrades"
                hash = "953b1b99bb5557fe86b3525f28f60d78ab16d56e9c3b4bbe75aba880f18cb6ad"

        strings:
                $b64_1 = "ZG8gbm90IHNjcmlwdA==" wide ascii // do not script
                $b64_2 = "Q2xpcEJvYXJkIExvZw==" wide ascii // ClipBoard Log
                $b64_3 = "RW5nIFdpe" wide ascii // Eng Wiz
                $b64_4 = "SEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25c" wide ascii // HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\
                $b64_5 = "Q3JNb2RNbmdy" wide ascii // CrModMngr
                $b64_6= "JVBER" wide ascii // Embedded data
                $b64_7 = "qQAAMAAAAEAAAA" wide ascii // Embedded data
                $str_1 = "Eng Wiz" wide ascii nocase
                $str_2 = "Engr Whizzy" wide ascii nocase
                $str_3 = "ClipBoard Log" wide ascii 
                $str_4 = "Keylogger Log" wide ascii 
                // ᚰᚣᛓᚦᚸᚸ᚜ᚨᚻᚼᚱᚻ --> decodes to SEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu --> decodes to HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
                $hex_reg = { b0 16 a3 16 d3 16 a6 16 b8 16 b8 16 9c 16 a8 16 bb 16 bc 16 b1 16 bb 16 } 
                // MD5 hashing func
                $hex_md5_func = { 73 46 01 00 0A 0A 28 30 01 00 0A 02 6F 98 00 00 0A 0B 1F ?? 28 7D 00 00 0A } 

        condition:
                uint16(0) == 0x5A4D and ((3 of ($b64*)) or (3 of ($str*)) or (any of ($hex*)))
}
```

## Sample Hashes
```
500cff9ba9d7b2632e61b0bcc8cbfd2f121f693efd4819932c9becf3d4d9d793
bb70dcdaa7ab425dbc04c841146e337c6ce0e2785bd1ee58e20f35dc310280a1
8e7ce09e1ebd3b7615b40c33b223732e11904bf967f9bc6242e0c2db2b82f326
c37175835189c295600b3a0c834e0b072f4f6afe05e3cae15172c3f4b1a9d36c
fc925bba0b3237445eea496be4ec85081e53ac2b63178da6328815b41f695b5c
28dd5a6ff7b507cad6d6017bd76f2bfc3c4cbdb0e540220ed7a0d8bc0b7d78be
49f5adde0e35b8d660ef5429844e509dc570165cb057ca7235108fa4dee465e3
497c438592c2f769ea5c1ae74f98ddc162cf54791d540db7e2ec6999e59f5939
```

## C2 Pattern
```
htt[p|s]://domain.[com|tk|usa.cc|???]/[a-z].php?[0-9]+
```

## Sample C2s
```
http[:]//devcommsync[.]tk/0[.]php?179
http[:]//locdbmngr[.]tk/l[.]php?8406129
http[:]//locdbmngr[.]c0m.at/l[.]php?7435800
http[:]//locdbmngr[.]usa.cc/l[.]php?990831
http[:]//locdbmngr[.]tk/l[.]php?1841837
http[:]//locdbmngr[.]c0m.at/l[.]php?1493172
http[:]//locdbmngr[.]usa.cc/l[.]php?7556458
http[:]//locdbmngr[.]tk/l[.]php?8963871
http[:]//locdbmngr[.]c0m.at/l[.]php?5027157
http[:]//locdbmngr[.]usa.cc/l[.]php?4678492
http[:]//locdbmngr[.]tk/l[.]php?6085906
http[:]//guimacdgt[.]tk/e[.]php?103
http[:]//extlanweb.ze[.]tc/o[.]php?89
http[:]//extlanweb[.]tk/o[.]php?91
http[:]//extlanweb[.]com/o[.]php?140
```