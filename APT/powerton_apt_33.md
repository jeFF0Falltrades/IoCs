# POWERTON (APT33)

## Reporting
* https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html
* https://www.symantec.com/security-center/writeup/2019-062513-4935-99

## YARA
```yara
rule apt_33_powerton {
    meta:
        author = "jeFF0Falltrades"
        hash = "6bea9a7c9ded41afbebb72a11a1868345026d8e46d08b89577f30b50f4929e85"

    strings:
        $str_wmi = "Adding wmi persist ..." wide ascii
        $str_registery = "Poster \"Registery Value With Name" wide ascii
        $str_upload = "(New-Object Net.WebClient).UploadFile(\"$SRVURL$address\", \"$fullFilePath" wide ascii
        $str_pass = "jILHk{Yu1}2i0h^xe|t,d+Cy:KBv!l?7" wide ascii
        $str_addr = "$address=\"/contact/$BID$($global:rndPost)/confirm" wide ascii
        $str_png = "$env:temp + \"\\\" + $(date -format dd-m-y-HH-mm-s) + \".png" wide ascii
        $str_msg = "/contact/msg/$BID$($global:rndPost)" wide ascii
        $str_ua = "Mozilla/5.0 (Windows NT $osVer; rv:38.0) Gecko/20100101 Thunderbird/38.1.0 Lightning/4.0.2" wide ascii
        $domain = "backupaccount.net" wide ascii

    condition:
        2 of ($str*) or $domain
}
```

## Sample Hash
```
6bea9a7c9ded41afbebb72a11a1868345026d8e46d08b89577f30b50f4929e85
```

## Sample C2
```
backupaccount[.]net
```
