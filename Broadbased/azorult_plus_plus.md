# Azorult++

## Reporting
* https://securelist.com/azorult-analysis-history/89922/

## YARA
```yara
rule azorult_plus_plus {
	meta:
		author = "jeFF0Falltrades"
		hash = "9d6611c2779316f1ef4b4a6edcfdfb5e770fe32b31ec2200df268c3bd236ed75"

	strings:
		$rdp = "netsh firewall add portopening TCP 3389 \"Remote Desktop\"" wide ascii nocase
		$list_1 = "PasswordsList.txt" wide ascii nocase
		$list_2 = "CookieList.txt" wide ascii nocase
		$coin_1 = "Ethereum\\keystore" wide ascii nocase
		$c2_1 = ".ac.ug" wide ascii nocase
		$hide_user = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist" wide ascii nocase
		$pdb = "azorult_new.pdb" wide ascii nocase
		$lang_check = { FF 15 44 00 41 00 0F B7 C0 B9 19 04 00 00 66 3B C1 } // call ds:GetUserDefaultLangID; movzx eax, ax; mov ecx, 419h; cmp ax, cx

	condition:
		$pdb or 5 of them
}
```

## Sample Hashes
```
9d6611c2779316f1ef4b4a6edcfdfb5e770fe32b31ec2200df268c3bd236ed75
d40fe5d71016f09035543b3686679be070ced21762c054750a96517929fac28c
```

## Sample C2
```
http[:]//ravor[.]ac[.]ug/
http[:]//rsman[.]ac[.]ug/
```
