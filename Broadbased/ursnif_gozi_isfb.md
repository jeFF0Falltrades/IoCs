# Ursnif/Gozi/ISFB/Dreambot

## Reporting
* https://www.fortinet.com/blog/threat-research/ursnif-variant-spreading-word-document.html

## YARA
```yara
rule ursnif_zip_2019 {
  meta:
    author = "jeFF0Falltrades"
    reference = "https://www.fortinet.com/blog/threat-research/ursnif-variant-spreading-word-document.html"

  strings:
    $doc_name = { 69 6e 66 6f 5f ?? ?? 2e ?? ?? 2e 64 6f 63 } // info_MM.DD.doc
    $zip_header = { 50 4B 03 04 }
    $zip_footer = { 50 4B 05 06 00 }

  condition:
    ($zip_header at 0) and ($doc_name in (0..48)) and ($zip_footer in (filesize-150..filesize))
}

rule ursnif_dropper_doc_2019 {
  meta:
    author = "jeFF0Falltrades"
    reference = "https://www.fortinet.com/blog/threat-research/ursnif-variant-spreading-word-document.html"

  strings:
    $sleep = "WScript.Sleep(56000)" wide ascii nocase
    $js = ".js" wide ascii
    $ret = { 72 65 74 75 72 6e 20 22 52 75 22 20 2b 20 22 5c 78 36 65 22 } // return "Ru" + "\x6e"
    $pse = { 70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 6e 63 20 } //powershell -Enc

  condition:
    uint16(0) == 0xcfd0 and all of them
}
```

## Sample Dropper Doc Hashes
```
b3c9c6d6179ba84fd485afc4818e2a4fe58ec38a05b3efbf1f0a2ab99ebbfef7
993311b373695ae9e8af053e70eb367343bae2537fb468c3a548725d80b735dc
6e46be288848568ad8402206cfce3fb870fb87756e497b7fd9288eef61c49149
051cd26d76ba66f9a7dcde2dc3da324f5db6b0cecde13da03f29ecb7f9f845ea
40b5902adf7d40f47f364da703c721bf7695c5b992c62fff436b716e009bac10
d651c084f35d5c7e7a85465315ae41ee7798b9adcd68851b0ed60794a5ca0350
60e7c3fa50b13cc33395faf0a61e601a0e6d2d25a2437a5762d56f3dcf8e726d
0f00ef22f1cbd2fe47bdbdc527cf45844bd4cb4c309153a2865977aa0ae17cd1
c7296822332bf2e847fcc1eeb5fbecccbeb6a035b1363427a5874c003bd13a4d
9f98fe5848818c238a98f94086a519510f39435acbc6dab640951f441d7c67fc
c816b27a6ff57c930a1da2ea77b8924765e719f8893d90663089c1bb1fbb167e
abd8b974612364e60785b3cab8f7a3ea8e430718955c8903aa7b460612f746d1
3c6b32b668105af6cda80bd03127be703f1b2848f3d1ca44edcb23cc0660e719
64365a632899c43616fae757dd3b5eea01bc30bfc637aa32e35201c976895a6e
daad58b57e00fe31dc1a8bb5a5ab5e758932ecd6630a9c7ab3cfc53aed089df6
5bbce914f9bc715051e5bb8004e551af580f84da23e9a8a6f04337a00777ff29
47a4c07a17666e71695d033af810b922ce12efc8817e31c7e81a4e9aeef77753
7ae94f84e63866b165184e7db53ccd7cf9ea1e06a2c235d85e30ed1a23f99be1
83c0731489f0b31359a526265ab316b8b227cf14cd2590dcabfa931c87fb9376
```

## Sample Ursnif Download URLs
```
http[:]//zvaleriefs96[.]com/qtra/ttqr[.]php?l=qena2.j12
http[:]//mgregyoherminio[.]com/qtra/ttqr[.]php?l=geus10.j12
http[:]//p813632eliza[.]com/qtra/ttqr[.]php?l=apqo4.j12
http[:]//zai55io72[.]com/qtra/ttqr[.]php?l=geus7.j12
```

## Sample Ursnif Payloads
```
0f68f619c4aa8d14ae5331f513b419c0cd9914a721d249bcb671ba925dc4d515
f1e4872848ae174c9a11ff0b9a2f0f3b1afea3ec2dc9a60fe8e91410f0ea3edf
8096e2a2d5e9cb41a6b9e89e824fc922fc9a74e20606713964df739d7948a202
67c4dba70e165b5bcace38636ede6222af0ecd0d8df1c76df3e2e312cfb340f9
6141f4a4af4243e8891c5df29519ba3a2d88ad8e2e749f6ac76f85053204eb92
74959ea83fed1847bae3e36c50e96b60cc43b60642b5a164a42e636be7f1828c
497ca1bb5accf15939f8683f63299cc45c4b2f5bae1b470747dff0983e191f10
3d78850ad41de15660d047f330549a679ba92174f2c1e023d507f303a974161b
2aa1066cac1baaf89df3a4173df7a57d2c1916db7439d93969c0ffe88197e866
48063d9a522090599f0508510548f5857b401d6affa9371471f19bc938d35eca
```