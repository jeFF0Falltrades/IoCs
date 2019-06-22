# NanoCore RAT

## Reporting
* https://www.cyber.nj.gov/threat-profiles/trojan-variants/nanocore
* https://www.stratosphereips.org/blog/2018/9/7/what-do-we-know-about-nanocore-rat-a-review

## YARA
```yara
import "pe"

rule nanocore_rat {
    meta:
        author = "jeFF0Falltrades"
    
    strings:
        $str_nano = "NanoCore.ClientPlugin" wide ascii
        $str_plg_1 = "Plugin [{0}] requires an update" wide ascii
        $str_plg_2 = "Plugin [{0}] is being uninstalled" wide ascii
        $str_conn_1 = "PrimaryConnectionHost" wide ascii
        $str_conn_2 = "BackupConnectionHost" wide ascii
        $str_id = "C8AA-4E06-9D54-CF406F661572" wide ascii
        // Loop used to load in config
        $load_config = { 02 06 9A 74 54 00 00 01 0B 02 06 17 58 9A 28 3A 00 00 0A }
    
    condition:
        2 of ($str_*) or $load_config or (pe.timestamp == 1424566177)
}

rule nanocore_surveillance_plugin {
    meta:
        author = "jeFF0Falltrades"
    
    strings:
        $str_name = "SurveillanceExClientPlugin.dll" wide ascii
        $str_keylog = "KeyboardLogging" wide ascii
        $str_dns_log = "DNSLogging" wide ascii
        $str_html_1 = "<td bgcolor=#FFFFF0 nowrap>.+?<td bgcolor=#FFFCF0 nowrap>(.+?)<td bgcolor=#FFFAF0 nowrap>(.+?)<td bgcolor=#FFF7F0 nowrap>.+?<td bgcolor=#FFF5F0 nowrap>.+?<td bgcolor=#FFF2F0 nowrap>.+?<td bgcolor=#FFF0F0 nowrap>.+?<td bgcolor=#FCF0F2 nowrap>.+?<td bgcolor=#FAF0F5 nowrap>(.+?)<td bgcolor=#F7F0F7 nowrap>" wide ascii
        $str_html_2 = "<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>" wide ascii
        $str_html_3 = "/shtml \"{0}\"" wide ascii
        $str_rsrc_lzma = "Lzma" wide ascii
        $str_nano = "NanoCore.ClientPlugin" wide ascii
        $str_pass_tool = "ExecutePasswordTool" wide ascii
        $get_raw_input = { 20 03 00 00 10 12 02 12 04 02 7B 09 00 00 04 28 C8 00 00 06 } // GetRawInputData Loop
        $get_dns_cache = { 12 02 7B 62 00 00 04 7E 7F 00 00 0A 28 80 00 00 0A 2C B5 }   // GetDNSCacheDataTable Loop    
    
    condition:
        (all of ($get_*)) or (3 of ($str_*)) or (pe.timestamp == 1424566189)
}
```

## Sample Hashes
### Primary Module
```
2b23d96749dc62144e34f377c40b66fe0978570193b1ff29df41cfe1e0088a8b
525e44aa7ade3e14fdf431074a78a9134ffbbd5acbb04515d72a60172c0234d8
ee0ad345a373f9e47e03e010544d45f7aa63c001bb2902bb74949e2f37d332cb
4fa02fe8de726f1d3597a4bbf67cca84114ea912f2486ebbc41ddb7f2dadb429
495c7f09c0b5fc9a220bd56807ce762c27da00a60f2c2cb29e44549d4ff98aa7
a8bbf4b26d893701a503f55fc25f6a97a5e0037dbca074ed2abbe42049d24a68
4145233af81f9b126c1162377d19d44c46c4f324995972870a40fc1759b7b5d8
a2159d09557fb67cad61c9d67c07876472cdcecc1f44e3924146d95c75ccb614
22959c7bcf21e80fff8949a840bd016770e1f57bccdee94fe03fc47edd874a0d
daf4a81c306c12b805bda6522dd7ad57d1b0c3ac32f919fb9816ac127653fdc2
d9612df3f723a1d7b5ad0da87fe9e9b0fbf68557e905c2dfac8ef428dd1bacf2
162f74dae55b7c2f7e5bc3ed32ccfcc1fb238cda4be9f652417155e3e1dcc92a
4c18c1035907894538f9f132cf38372af97a6e60acea650c8fea0760961f9427
504112875ddd73d6b2b823e1b712158a9e86485912d05e6b2d5f309b59d1c48f
f5afb4fb921bd2a13a52d09d3706f7a2f7cb048824c84b780a03b3aa69f59ab7
c0d6f12fd9a1330fcdd66d0dd98b6d5e6146a45a6f262a2b243541ce034135d8
9eff2850fbc728f57dbf9e6eff0db1da23755890f1f5efcb946b7d9e6639789c
61a483debf342aebff4c78b1942c2c0d7497e51b9c2e897176efe154d6b221d3
3d10dbe069be5697108b046bfdac184ec9164bc10432c4fef5d25a6639a4f8be
f1deb1e1e89d5893f103beabd99659a1520834d30f9411c1f456255c7553b5d4
```

### Surveillance Plugin
```
db86d3cc11f42a9c4a478b6afe36943827964de9dc0d1fc8ee3489ccc1a6e088
01e3b18bd63981decb384f558f0321346c3334bb6e6f97c31c6c95c4ab2fe354
```