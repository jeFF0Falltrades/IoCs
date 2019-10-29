# DTrack 
### Utilized by North Korean APT "Lazarus Group"; Not to be confused with ATMDtrack

## Reporting
* https://usa.kaspersky.com/about/press-releases/2019_dtrack-previously-unknown-spy-tool-hits-financial-institutions-and-research-centers

## YARA
```yara
rule dtrack_2019 {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $str_log = "------------------------------ Log File Create...." wide ascii
        $str_conn = "=================== Connection Status ===================" wide ascii
        $str_ua = "CCS_Mozilla/5.0 (Windows NT 6.1" wide ascii
        $str_chrome = "Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\History" wide ascii
        $reg_use = /net use \\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\C\$ \/delete/
        $reg_move = /move \/y %s \\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\C\$\\Windows\\Temp\\MpLogs\\/

    condition:
        2 of them
}
```

## Sample Hashes
```
bfb39f486372a509f307cde3361795a2f9f759cbeb4cac07562dcbaebc070364
3cc9d9a12f3b884582e5c4daf7d83c4a510172a836de90b87439388e3cde3682
51ac3966b48c91947de4ce51a90aee9deb730d86cedf8c863d9dcdf0fb322537
```
