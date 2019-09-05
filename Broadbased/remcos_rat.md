# Remcos RAT

## Reporting
* https://www.fortinet.com/blog/threat-research/remcos-a-new-rat-in-the-wild-2.html
* https://breaking-security.net/remcos/

## YARA
```yara
import "pe"

rule remcos_rat {
 meta:
     author = "jeFF0Falltrades"
 
 strings:
     $str_upload = "Uploading file to C&C" wide ascii
     $str_keylog_1 = "Offline Keylogger Started" wide ascii
     $str_keylog_2 = "Online Keylogger Started" wide ascii
     $str_mutex_1 = "Mutex_RemWatchdog" wide ascii
     $str_mutex_2 = "Remcos_Mutex_Inj" wide ascii
     $str_cleared = "Cleared all cookies & stored logins!" wide ascii
     $str_bs_vendor = "Breaking-Security.Net" wide ascii
     $str_controller = "Connecting to Controller..." wide ascii
     $str_rc4 = { 40 8b cb 99 f7 f9 8b 84 95 f8 fb ff ff 8b f3 03 45 fc 89 55 f8 8d 8c 95 f8 fb ff ff 99 f7 fe 8a 01 8b f2 8b 94 b5 f8 fb ff ff } // RC4 PRGA

 condition:
     3 of ($str*) or (pe.sections[0].name == "VVR" and pe.sections[1].name == "ZKZR" and pe.sections[2].name == ".test" and pe.sections[3].name == "rca" and pe.sections[4].name == "vga")
}
```

## Sample Hashes
```
840eee72e539982e4169b5c6a52576ef539e0afd42d4d69752a9c04e4f218a0e
d24c93170a786027bb9eef98b6eddaaca10c21f9608d5fbdfb60a2a4f3b9fa70
ab76cc360966833c77b9f15e0f1d61133f65e08f6839bd7665771943e7e286b8
37183bfcc860d028ac402aa0546d3e53e14afe89054c82603b07362198cd2fb9
3043c9cf55b4364d8559ec7bf89af38ae8ed6dc100a3d532089297d8eecd8e9f
35444cffb383b8ab4070d94d286c54f94229a844c7663d4e4afb511cb886f3b4
be39f694a62f09a05fc1286e2914ee4c8c09429719293026606e3b08bb5cb311
198799e167eeed34266d190082f6d7f14954dad85ecdb0c9053bcbc0feb075ff
0b53950436346bf9ae77747026686053b54a6c5600004f89b1f7968d77ea1319
a114518c4dea54adb5c7933b6e98c5dd125b49f167c5e371e599a2fc8983c6bb
bfca4bf41c7d751187f408585f52c312d5e0fc8a1ba5cba8c0dd6edf45985142
7c29126f02f501ceca91476362d3943814bdb4340c581fdcfd2b9673211a6d43
2a8b0604d56a758edc3bd072e547cff82eff121d4b29fc85dd9862b2bc42b61c
32cadf221a9a0a879aeb3d16649572046ccb87db256185b040013a03d1636d56
0f09141942787e94a4c4c6ef4abb62b405dfdff85c428325b0d5e4c8494b8b65
643b467b305a14923d0d1fbca75a89f4e9c04a4cf8898971fa02547c756ebf0c
3002ae236ce2973c6af6e800eb2df64d5f6d548771fe3f323be6c82ba958f7cf
14a96f07308f4657248a763be17ccc3d51831438dea0830e52a551113f919faf
d0f00421a8529da13817ea9d6264966f887609827dd53151ca142b5cb8572d43
bc80d73322a4fb9b3bde5cb565a53dde0ea64aab5babfb241615c78fec4c55b0
b37891704d02a745df80bbbe41c8844adbbca95f1bb8e34e241bd9490f3a4130
198c9582805f40fb1be77025da81c3ea6084e56f7146b06a07c2a8f628bb8374
0b450fc70bdc9968e6abafb29c703eab3711725b649ed87aaed31ebdf403032e
4b30343d6c9ef737bb2e9c9decfceed3601758482f3c5b64657831ad91b77950
6235f925b478a8c2ce18fcca4eed116262c1ca77d4dc8826e20659d945a475d4
3ea110c01b74870b3c3963fcd9eaecd3001e86bf6568620741f4a9eb3bc56b77
bf320fe9a5dc90580aaf6f4d8b41cda25513bf4be6e78d95a3e16e96aef996f1
9228effc9fc68fc21884bdb01faccca82807621a9be37df91de7f471bfae4c32
cdd61c4fac8974ba7ecf72fc54be7ea0127166f48569eccc468d691dcc125aae
9c8fa9ab417ca4785ac38dd8c8764fcebdddb3f287718352576a189252744acf
a60f1b6ff710efa978ac06e5cc94dc85b62c964feb10d1e2a9ad1da9b6a7be83
d1d6a1daf82e27a76d1497322df47cd1b56ae86a2fcfdd6f0bdccf387713b339
01bb0092ad25ebb1a272be4ef82a6a44f10d0687fb6af479c9a4a1804b3da193
64aaf0cf3145960ae60602c46b01bd43760d34e279cb2d8139811526076565cd
252cd749123f995db15c52dfe01a2df021050943af5e26d07b888cc5f1f1f75a
3e411992149590cea9a2206e53f34a5059e5c09f701f21818e7b13eb065897ec
```
