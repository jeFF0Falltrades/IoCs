# MegaCortex

## Reporting
* https://news.sophos.com/en-us/2019/05/03/megacortex-ransomware-wants-to-be-the-one/
* https://twitter.com/GossiTheDog/status/1124403699508551680

## YARA
```yara
import "pe"

// Fires on discovered MegaCortex samples using certificate signatures
rule megacortex_payload {
    meta:
        author = "jeFF0Falltrades"
        reference = "https://news.sophos.com/en-us/2019/05/03/megacortex-ransomware-wants-to-be-the-one/"

    condition:
        uint16(0) == 0x5a4d and ((for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial == "04:c7:cd:cc:16:98:e2:5b:49:3e:b4:33:8d:5e:2f:8b" or pe.signatures[i].serial == "71:a0:b7:36:95:dd:b1:af:c2:3b:2b:9a:18:ee:54:cb")) or pe.imphash() == "81da9241b26f498f1f7a1123ab76bb9d")
}

// Fires on the batch file used to stop AV/other services running prior to executing the MegaCortex payload (NOTE: May not be exclusive to MegaCortex)
rule megacortex_av_bat {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $str_1 = "taskkill /IM agntsvc.exe /Ftaskkill /IM dbeng50.exe /F"
        $str_2 = "net stop SQLAgent$SOPHOS /ynet stop AVP /y"
        $str_3 = "net stop \"Sophos Clean Service\" /y"
        $str_4 = "net stop \"Sophos Device Control Service\" /y"
        $str_5 = "net stop \"Sophos File Scanner Service\" /y"
        $str_6 = "net stop \"Sophos Health Service\" /y"
        $str_7 = "net stop \"Sophos MCS Agent\" /y"
        $str_8 = "net stop \"Sophos MCS Client\" /y"
        $str_9 = "net stop \"Sophos Message Router\" /y"
        $str_10 = "net stop \"Sophos Safestore Service\" /y"
        $str_11 = "net stop \"Sophos System Protection Service\" /y"
        $str_12 = "net stop \"Sophos Web Control Service\" /y"
        $str_13 = "sc config VeeamHvIntegrationSvc start= disabled"
        $str_14 = "sc config MSSQL$VEEAMSQL2012 start"
        $str_15 = "sc config SQLAgent$CXDB start= disabled"
        $str_16 = "taskkill /IM zoolz.exe /F"
        $str_17 = "taskkill /IM agntsvc.exe /Ftaskkill /IM dbeng50.exe /F"
        $str_18 = "taskkill /IM wordpad.exe /F"
        $str_19 = "taskkill /IM xfssvccon.exe /F"
        $str_20 = "taskkill /IM tmlisten.exe /F"
        $str_21 = "taskkill /IM PccNTMon.exe /F"
        $str_22 = "taskkill /IM CNTAoSMgr.exe /F"
        $str_23 = "taskkill /IM Ntrtscan.exe /F"
        $str_24 = "taskkill /IM mbamtray.exe /F"
        $str_25 = "iisreset /stop"

    condition:
        5 of them
}

// Fires on the ransom note left behind MegaCortex ("!!!_READ_ME_!!!.txt")
rule megacortex_ransom {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $megacortex = "corrupted with MegaCortex" nocase
        $tsv = ".tsv"
        $morpheus = "We can only show you the door"
        $files = "email to us 2 files from random computers"

    condition:
        2 of them
}

// (WIP) Fires on meterpreter payloads found beaconing to a C2 discovered in the MegaCortex attacks (89[.]105[.]198[.]28)
rule megacortex_meterpreter {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $cert = "Bud. 120-A, Vul. Balkivska1"

    condition:
        uint16(0) == 0x5a4d and $cert and (for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial == "00:CA:0E:70:90:D4:82:70:04:C9:9A:F2:FC:7D:73:3C:02" or pe.signatures[i].serial == "1D:A2:48:30:6F:9B:26:18:D0:82:E0:96:7D:33:D3:6A" or pe.signatures[i].serial == "01:FD:6D:30:FC:A3:CA:51:A8:1B:BC:64:0E:35:03:2D" or pe.signatures[i].serial == "03:01:9A:02:3A:FF:58:B1:6B:D6:D5:EA:E6:17:F0:66" or pe.signatures[i].serial == "06:FD:F9:03:96:03:AD:EA:00:0A:EB:3F:27:BB:BA:1B" or pe.signatures[i].serial == "0C:E7:E0:E5:17:D8:46:FE:8F:E5:60:FC:1B:F0:30:39"))
}

// (WIP) Fires on Rietspoof samples found loading MegaCortex based on certificates (
rule megacortex_rietspoof {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $cert = "8 Quarles Park Road1"
    
    condition:
         uint16(0) == 0x5a4d and ($cert or (for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial == "53:CC:4C:69:E5:6A:7D:BC:36:67:D5:FF:D5:24:AA:4B" or pe.signatures[i].serial == "1D:A2:48:30:6F:9B:26:18:D0:82:E0:96:7D:33:D3:6A" or pe.signatures[i].serial == "13:EA:28:70:5B:F4:EC:ED:0C:36:63:09:80:61:43:36" or pe.signatures[i].serial == "0E:CF:F4:38:C8:FE:BF:35:6E:04:D8:6A:98:1B:1A:50" or pe.signatures[i].serial == "7E:93:EB:FB:7C:C6:4E:59:EA:4B:9A:77:D4:06:FC:3B" or pe.signatures[i].serial == "00:AD:72:9A:65:F1:78:47:AC:B8:F8:49:6A:76:80:FF:1E" or pe.signatures[i].serial == "01:FD:6D:30:FC:A3:CA:51:A8:1B:BC:64:0E:35:03:2D")))
}
```

## Sample Hashes
#### MegaCortex Payloads
```
f5d39e20d406c846041343fe8fbd30069fd50886d7d3d0cce07c44008925d434
b4a65070354d2a89e84b5ddae81a954a868a714a248a48b72c832c759d85558a
11f7bb37dd425150e6b095a8d1f3a347ee83e604302a4d9bb201900e74a81d73
ab654745b33aabac9c8e4ba1d0040be1c44ac50d0090b4759d4ef1aa04d55947
0858bc69e02c730a55f760f01374bdc378aaff806478d1c18f9e587d7121b56a
80b9629ea3a33dc26f2ed3a2f8d3293cc3684f544011f1c4b96d4104d392497f
598ee9ee6ad4467ddf4b4d325cb15928fd692da8d6e1c8980d2d86d97ea2f4f9
```

#### Meterpreter Payloads Contacting Reported MegaCortex C2
```
513c78582f4e51a448aafffb006af5ae1b2ace47b20c5f5eb16d354f75592ad6
f01767bc1aca7b06b54f94f872e0286b0e5bd4779e49d01ac01e4cc41141b57d
b4e1a2cb3f1cfe6c075ab6639e775c716507a047dcecf66815b50134fc446cb9
d67e9412d83e5d31f46f8db8f688e74d00c06741d2b5ef7f37a5cd806217fce5
ecce00620189b0fe9f690bfeb67007ded3f97023fbc15972c18d22646f5702f2
e344c59f507bd993a0abab39ef06cd477b1728fc12a7fb71da34a11a14801e25
c54fc30bdbf03b2c23223e976158d3490f2eb4e1c6b79a7d08ab4eb96d2aeb49
b1faf39b92816680b2fa16c2a911d2f40dbe0c6d1b400b28945b8434307dee5b
122dc72e10a25d1285bddb70fb0e26e91e298b1adaa0fdff6becf13cdfa34e36
```

#### Rietspoof Samples Contacting Reported MegaCortex C2
***For YARA to Rietspoof in general, see James_inthe_Box's signature [here](https://pastebin.com/YL7vZ8wz)***

```
9097f3cbedc79d1c1b91a0c3e776c19d07cb233d79e4af6f325e8d5d537348c2
25d7718dc30eccd1a9a2bc037a49b98c503f8064a55a009b1818ba448bcad27b
523fcda29655bec72d941311e70e7e810cc5a040d527fb5739120e36fee2e5df
f5d739b5b15530be8acafc0f4f358ec48efbe3b1a5d7debbf94bed17b2a3b940
```

#### Batch Files to Stop Security/Other Services
```
5f815b8a8e77731c9ca2b3a07a27f880ef24d54e458d77bdabbbaf2269fe96c3
bb04c52aa52afc55da5dbd4fda8517973ccd6a826ca0146ed158323db3c3f630
6c21a1a0b77ec41a214e0fdbc0aeb088ccab6e8b01d90f506e7526843faa6fdd
40f03dd7c6388c3f1ce7fabc0f76949c4379d278163f2c313a6a43afaed2ccf9
3ee9b22827cb259f3d69ab974c632cefde71c61b4a9505cec06823076a2f898e
```
