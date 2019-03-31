# KleptoParasite

## Reporting
* https://malpedia.caad.fkie.fraunhofer.de/details/win.kleptoparasite_stealer

## YARA
```yara
rule kleptoparasite {
 meta:
     author = "jeFF0Falltrades"
     hash = "2109fdb52f63a8821a7f3efcc35fa36e759fe8b57db82aa9b567254b8fb03fb1"

 strings:
     $str_full_pdb = "E:\\Work\\HF\\KleptoParasite Stealer 2018\\Version 3\\3 - 64 bit firefox n chrome\\x64\\Release\\Win32Project1.pdb" wide ascii nocase
     $str_part_pdb_1 = "KleptoParasite" wide ascii nocase
     $str_part_pdb_2 = "firefox n chrome" wide ascii nocase
     $str_sql= "SELECT origin_url, username_value, password_value FROM logins" wide ascii nocase
     $str_chrome = "<center>Google Chrome 64bit NOT INSTALLED" wide ascii nocase
     $str_firefox = "<center>FireFox 64bit NOT INSTALLED" wide ascii nocase
     $str_obf = "naturaleftouterightfullinnercross" wide ascii nocase
     $str_c2 = "ftp.totallyanonymous.com" wide ascii nocase
     $str_fn = "fc64.exe" wide ascii nocase


 condition:
     3 of them
}
```

## Sample Hashes
```
2109fdb52f63a8821a7f3efcc35fa36e759fe8b57db82aa9b567254b8fb03fb1
05a6a1bf352673dfd6ce40a74e70b1b65da839dba0cb2f058a702f4f9d99d415
a153178a7fa6cf7a1d983044414c1a2bfd0cc803bea032fd06f5e1a770be8cec
b30a8d6399e97ab14306c92cb493e2452437637f6f951cc7074e46edb7ea5e85
764b8e0901100b9bda07db4fc2f7de719dc14b3a828d2f05b9616c2a49b182d2
858c52f842df33640f505f1944a2032ba338a2ad819bab785693479cf82874f0
c68656ecf0879bc12f386e98005f142f12210866a877e1d10550690c041f03f6
5f0534dcbd1345ad38ac00a75a8f82b9dd36ac809315bd4662ecad894437fccb
5d316d95ad1d04e927fb21a099d1419563ac13f976e994c462740d3f8c97556d
860e0a164afffb5eba5ee403a8c16482c4b212249cf70468ce45648147f5dccf
9a96149acffebb4209a7c94eaff4d46c205e3f9648ea9bd2739235147104c81f
9ffad2113118175a24c6d0d5641a02b8a43794fee22984142d7fb56999bf8a62
7ffcb6b724343df1024e663f8d4edd6723dfdd3f103e383f64f0e76842f981f8
bd045d5ecb770c80d194578536f9c5e9ff0cce1f2f99c82ce59cdf801a2daaa0
```

## Sample C2
```
ftp[.]totallyanonymous[.]com
```
