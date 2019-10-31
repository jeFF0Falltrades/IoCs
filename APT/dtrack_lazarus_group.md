# DTrack 
### Utilized by North Korean APT "Lazarus Group"; Not to be confused with ATMDtrack

## Reporting
* https://usa.kaspersky.com/about/press-releases/2019_dtrack-previously-unknown-spy-tool-hits-financial-institutions-and-research-centers
* https://twitter.com/a_tweeter_user/status/1188811977851887616?s=20

## YARA
```yara
rule dtrack_2019 {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $str_log = "------------------------------ Log File Create...." wide ascii
        $str_ua = "CCS_Mozilla/5.0 (Windows NT 6.1" wide ascii
        $str_chrome = "Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\History" wide ascii
        $pdb = "Users\\user\\Documents\\Visual Studio 2008\\Projects\\MyStub\\Release\\MyStub.pdb" wide ascii
        $str_tmp = "%s\\~%d.tmp" wide ascii
        $str_exc = "Execute_%s.log" wide ascii
        $reg_use = /net use \\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\C\$ \/delete/
        $reg_move = /move \/y %s \\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\C\$\\Windows\\Temp\\MpLogs\\/

    condition:
        2 of them or $pdb
}
```

## Sample Hashes
```
3cc9d9a12f3b884582e5c4daf7d83c4a510172a836de90b87439388e3cde3682
bfb39f486372a509f307cde3361795a2f9f759cbeb4cac07562dcbaebc070364
51ac3966b48c91947de4ce51a90aee9deb730d86cedf8c863d9dcdf0fb322537
61c1b9afa2347c315a6b4628f9dff3ada6f8d040345402d4708881f05b1ec48b
ee9cd8decf752a47eefe24369a806976dce8ac2c29a8271c68bc407326fb19a9
791c59a0d6456ac1d9976fe82dc6b13f3e5980c6cfa2fd9d58a3cc849755ea9f
93a01fbbdd63943c151679d037d32b1d82a55d66c6cb93c40ff63f2b770e5ca9
a0664ac662802905329ec6ab3b3ae843f191e6555b707f305f8f5a0599ca3f68
c5c1ca4382f397481174914b1931e851a9c61f029e6b3eb8a65c9e92ddf7aa4c
```
