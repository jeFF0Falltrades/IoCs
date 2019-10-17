# Formbook

## Reporting
* https://thisissecurity.stormshield.com/2018/03/29/in-depth-formbook-malware-analysis-obfuscation-and-process-injection/
* https://www.cyberbit.com/blog/endpoint-security/formbook-research-hints-large-data-theft-attack-brewing/

## YARA
```yara
// Fires on Formbook VB6 initial and extracted files
rule formbook_vb {
    meta:
        author = "jeFF0Falltrades"
        ref = "https://thisissecurity.stormshield.com/2018/03/29/in-depth-formbook-malware-analysis-obfuscation-and-process-injection/"

    strings:
        $hex_set_info = { 68 65 73 73 00 68 50 72 6F 63 68 74 69 6F 6E 68 6F 72 6D 61 68 74 49 6E 66 68 4E 74 53 65 54 EB 2C }
        $hex_decode_loop = { 81 34 24 [4] 83 E9 03 E0 F1 FF 34 0E 81 34 24 }
        $hex_anti_check = { 80 78 2A 00 74 3D 80 78 2B 00 74 37 80 78 2C 00 75 31 80 78 2D 00 75 2B 80 78 2E 00 74 25 80 78 2F 00 75 1F 80 78 30 00 74 19 80 78 31 00 75 13 80 78 32 00 74 0D 80 78 33 00 }
        $hex_precheck = { E8 AE FA FF FF 3D 00 03 00 00 0F 9F C2 56 88 56 35 E8 3D FC FF FF 56 E8 E7 F6 FF FF 56 E8 41 F9 FF FF 56 E8 AB F7 FF FF 56 E8 F5 DE FF FF }
        $str_marker = "r5.oZe/gg" wide ascii

    condition:
        2 of them
}
```

## Sample Hashes
```
9f1f7b561908f8effd0bd02dfba51178449c70f1420f89ac8f9a8bd08e28fa74
1ce17200496c6ffbbfe6220fa147f7599edce5a4dfb27a0afe14e072ceca5eb6
4e425e87fe99e62fb97a6a394638c7020b1fe2df3f814e77e3f9167def61e136
18800181c19e057ab483fe36354782a389a1fa1e68e469bb90a3274f4e8b6187
8203cca6a131c92b99a69777c4b4584c20d69a58c68b76c46d579dfb4c41f64d
61fc6c393dfa741ca4f50a1e44bd5f854f8a0240e2527958ea1cac5fb21eb6bb
```
