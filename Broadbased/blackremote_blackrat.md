# Blackremote (AKA BlackRAT)

## Reporting
* https://unit42.paloaltonetworks.com/blackremote-money-money-money-a-swedish-actor-peddles-an-expensive-new-rat/
* https://malpedia.caad.fkie.fraunhofer.de/details/win.blackremote

## YARA
```yara
rule blackremote_blackrat_payload_2020
{
    meta:
        author = "jeFF0Falltrades"
        ref = "https://unit42.paloaltonetworks.com/blackremote-money-money-money-a-swedish-actor-peddles-an-expensive-new-rat/"

    strings:
        $str_vers_1 = "16.0.0.0" wide ascii
        $str_vers_2 = "16.2.0.0" wide ascii
        $re_c2_1 = /%\*%\|[A-Z0-9]+?\|%\*%\|[A-Z0-9]+?\|%\*%\|[A-Z0-9]+?\|%\*%\|[A-Z0-9]+?/ wide ascii
        $re_c2_2 = /\|!\*!\|\|!\*!\|/ wide ascii
        $hex_rsrc = { 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A }

    condition:
        2 of them and (1 of ($re*) or $hex_rsrc)
}

rule blackremote_blackrat_proclient_2020
{
    meta:
        author = "jeFF0Falltrades"
        ref = "https://unit42.paloaltonetworks.com/blackremote-money-money-money-a-swedish-actor-peddles-an-expensive-new-rat/"

    strings:
	$str_0 = "K:\\5.0\\Black Server 5.0\\BlackServer\\bin\\Release\\BlackRATServerM.pdb" wide ascii nocase
	$str_1 = "BlackRATServerM.pdb" wide ascii nocase
	$str_2 = "RATTypeBinder" wide ascii nocase
	$str_3 = "ProClient.dll" wide ascii nocase
	$str_4 = "Clientx.dll" wide ascii nocase
	$str_5 = "FileMelting" wide ascii nocase
	$str_6 = "Foxmail.url.mailto\\Shell\\open\\command" wide ascii nocase
	$str_7 = "SetRemoteDesktopQuality" wide ascii nocase
	$str_8 = "RecoverChrome" wide ascii nocase
	$str_9 = "RecoverFileZilla" wide ascii nocase
	$str_10 = "RemoteAudioGetInfo" wide ascii nocase

    condition:
    	4 of them
}
```

## Sample Hashes
```
d7a80e707fe7febd8a4de922f15f1419b679fe8f3420a4a8ccf2bd2bb64c52e5
2b3cda455f68a9bbbeb1c2881b30f1ee962f1c136af97bdf47d8c9618b980572
105cab9c9604238c05be167c6d8d47cd2bc0427b07ede08c5571b581ebd80001
1737cf3aec9f56bb79a0c4e3010f53536c36a1fbeeedea81b6d7b66074ecffbe
3eda427ad5816e6dcf077562a367f71e8bdf5aa931e594416ae445357c12b409
93bfbd4b12a17732c8b7e66c554f98187184c6d845bd02e0dbb2104ce8da0453
c207cf50305f126451e2dc5493d83614fdf801541d011e5002ee5daea2b4433b
e1bf5d2ef3a4f922f9a15ab76de509213f086f5557c9e648126a06d397117d80
901e06cd91adb7255d75781ef98fac71d17f7bed074a52147bdbd42ea551b34f
129491bfdd9a80d5c6ee1ce20e54c9fb6deb2c1e1713e4545b24aa635f57a8b9
931839ee649da42b0ee3ac5f5dfa944b506336c7f4e5beb3fc07a6b35a7e6383
0c63983cb38d187c187f373852d7b87ff4e41ea0d77d75907aa3388ad957f38f
```
