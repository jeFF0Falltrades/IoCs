# Darktrack RAT

## Reporting
* https://news.softpedia.com/news/free-darktrack-rat-has-the-potential-of-being-the-best-rat-on-the-market-508179.shtml
* https://cracked.to/Thread-Release-RAT-Dark-track-alien-4-1
* https://www.facebook.com/darktrackrat/

## YARA
```yara
import "pe"

rule darktrack_rat {
	meta:
		author = "jeFF0Falltrades"
		hash = "1472dd3f96a7127a110918072ace40f7ea7c2d64b95971e447ba3dc0b58f2e6a"
		ref = "https://news.softpedia.com/news/free-darktrack-rat-has-the-potential-of-being-the-best-rat-on-the-market-508179.shtml"
		
	strings:
		$dt_pdb = "C:\\Users\\gurkanarkas\\Desktop\\Dtback\\AlienEdition\\Server\\SuperObject.pas" wide ascii
		$dt_pas = "SuperObject.pas" wide ascii
		$dt_user = "].encryptedUsername" wide ascii
		$dt_pass = "].encryptedPassword" wide ascii
		$dt_yandex = "\\Yandex\\YandexBrowser\\User Data\\Default\\Login Data" wide ascii
		$dt_alien_0 = "4.0 Alien" wide ascii
		$dt_alien_1 = "4.1 Alien" wide ascii
		$dt_victim = "Local Victim" wide ascii

	condition:
		(3 of ($dt*)) or pe.imphash() == "ee46edf42cfbc2785a30bfb17f6da9c2" or pe.imphash() == "2dbff3ce210d5c2b4ba36c7170d04dc2"
}
```

## Sample Hashes
```
dd656da791d7894410c7280c63be6212eb1f7e3ac75cd9d11a4a7f4bb2784234
7ddcf0910b52de0c7030c2d5990055c7b07db78701d157e4a139effdbfaf2eb1
5321e90067076894a2118606ef01f23c2e1668c82e594068ac336b546add36c1
1bd03e9e6a5a50916545c74e9649f4d2a7e3471f7df565152a41c584639e5178
4534f569c0e1eeea56bb336f2876f64214c9d68b39d40d3e430a1541043fa348
7a525beb09b87eab75b1123597d407cbcf01b15055220804dda650fe13bd63fa
500c3bd28257a9b071bc0acc09f528f1df30fbccf87fb88b2f4e3267ecd593cc
```