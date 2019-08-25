# Azorult++

## Reporting
* https://securelist.com/azorult-analysis-history/89922/

## YARA
```yara
import "pe"

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
		$pdb or 5 of them or pe.imphash() == "e60de0acc6c7bbe3988e8dc00556d7b9"
}
```

## Sample Hashes
```
9d6611c2779316f1ef4b4a6edcfdfb5e770fe32b31ec2200df268c3bd236ed75
d40fe5d71016f09035543b3686679be070ced21762c054750a96517929fac28c
79d77a60e2fd74542fed9c422f2cc2209adbee6f7ed6f0c0f93b01c1cec65a4b
388259fad4828dc37ffee14430de8ddfc7939008e1ff5c797952c01e59934073
a2217739290393aef966a2a8265a970f2efb37e78795036e7a6af037982e43fc
9ef3ca7f675165e1b64b4ec4766874f3293319975b72767401a1a6c545538f0d
5ec0b1c700f7f48c5a718e1e472d71b44af51b19874091836b2901b62197f2a4
939c4606178c3035a5787e2e6bdc0926f62045a181d822c309fc065a177e55c3
10fcbb0a7f7156c7c090ec14bdc621870a29933417cbd0e86599d67ba872309c
546f31401d79fb61ef9883a9b460b7c0a53156daaad25d0867ebc3351c0a58e9
1d52dff8e87cd957683836345513c665700f41a1ede71aefc6806bc0bc6d94e6
f38a801a0a91e1218bfe85d766e7c647baddc77bf8fdeb58704071e54c525973
c38997688f5a8b6efad3e78e368c48252e1c9d3b5a30d8d5218eacfe182ca464
0fa4a8b214e156a21812ced89733e79e8b5d070d63693e6e2f38306e1f66899d
38b49c53f496bfdec7294b240600f6cca0db783a6d669f42f0f1a6d3da203448
00ee298cd81fac628e8cb9a9e5bf480dcde43858f60f1d5d16ad46d5c2718e67
fa4d8040427c96f29edbc06e1ae89e52ac385d2cf8291d29185789e85d40969b
f705a22400466c382462d82e7040b72841cc458cec9d19a8d66e5bfbd4e663b9
df0191de79306193b7bebc9594c9f454e7c42bd53f8e93e02b5903bcdcf33b7e
60d47ef7ffd83322ec16006175ecee6f6875c7f998bb83daac2a6b8bcad7be3b
4daf0646b1ced5c12dee05c43a952dcde22110cc764b0bb565811d7321fb2192
cc127fd85514fdefae788cc63808b18bdc238f86284b075674a17dd292dcce70
```

## Sample C2
```
http[:]//ravor[.]ac[.]ug/
http[:]//rsman[.]ac[.]ug/
```
