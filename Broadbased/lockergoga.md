# LockerGoga

## Reporting
* https://doublepulsar.com/how-lockergoga-took-down-hydro-ransomware-used-in-targeted-attacks-aimed-at-big-business-c666551f5880
* https://labsblog.f-secure.com/2019/03/27/analysis-of-lockergoga-ransomware/

## YARA
```yara
rule lockergoga {
   meta:
      author = "jeFF0Falltrades"
      hash = "bdf36127817413f625d2625d3133760af724d6ad2410bea7297ddc116abc268f"

   strings:
      $dinkum = "licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED" wide ascii nocase
      $ransom_1 = "You should be thankful that the flaw was exploited by serious people and not some rookies." wide ascii nocase
      $ransom_2 = "Your files are encrypted with the strongest military algorithms RSA4096 and AES-256" wide ascii nocase
      $str_1 = "(readme-now" wide ascii nocase
      $mlcrosoft = "Mlcrosoft" wide ascii nocase
      $mutex_1 = "MX-tgytutrc" wide ascii nocase
      $cert_1 = "16 Australia Road Chickerell" wide ascii nocase
      $cert_2 = {  2E 7C 87 CC 0E 93 4A 52 FE 94 FD 1C B7 CD 34 AF } //  MIKL LIMITED
      $cert_3 = { 3D 25 80 E8 95 26 F7 85 2B 57 06 54 EF D9 A8 BF } // CCOMODO RSA Code Signing CA
      $cert_4 = {  4C AA F9 CA DB 63 6F E0 1F F7 4E D8 5B 03 86 9D } //  COMODO SECURE

   condition:
      4 of them
}
```

## Sample Hashes
```
bdf36127817413f625d2625d3133760af724d6ad2410bea7297ddc116abc268f
8cfbd38855d2d6033847142fdfa74710b796daf465ab94216fbbbe85971aee29
bef41d3c76aa98e774ca0185eb5d37da7bf128e3d855ebc699fed90f3988c7d3
5b0b972713cd8611b04e4673676cdff70345ac7301b2c23173cdfeaff564225c
6e69548b1ae61d951452b65db15716a5ee2f9373be05011e897c61118c239a77
c7a69dcfb6a3fe433a52a71d85a7e90df25b1db1bc843a541eb08ea2fd1052a4
c3d334cb7f6007c9ebee1a68c4f3f72eac9b3c102461d39f2a0a4b32a053843a
f3c58f6de17d2ef3e894c09bc68c0afcce23254916c182e44056db3cad710192
C97d9bbc80b573bdeeda3812f4d00e5183493dd0d5805e2508728f65977dda15
b8dedd74f8f474c97d53d313eb5a61d09fc020e91aa09c36711bac5cc123b6d7 (Ransom Note)
```
