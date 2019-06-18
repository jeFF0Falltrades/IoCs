# Agent Tesla

## Reporting
* https://www.fortinet.com/blog/threat-research/analysis-of-new-agent-tesla-spyware-variant.html

## YARA
```yara
rule agent_tesla_2019 {
    meta:
        author = "jeFF0Falltrades"
        hash = "717f605727d21a930737e9f649d8cf5d12dbd1991531eaf68bb58990d3f57c05"

    strings:
        $appstr_1 = "Postbox" wide ascii nocase
        $appstr_2 = "Thunderbird" wide ascii nocase
        $appstr_3 = "SeaMonkey" wide ascii nocase
        $appstr_4 = "Flock" wide ascii nocase
        $appstr_5 = "BlackHawk" wide ascii nocase
        $appstr_6 = "CyberFox" wide ascii nocase
        $appstr_7 = "KMeleon" wide ascii nocase
        $appstr_8 = "IceCat" wide ascii nocase
        $appstr_9 = "PaleMoon" wide ascii nocase
        $appstr_10 = "IceDragon" wide ascii nocase
        // XOR sequence used in several decoding sequences in final payload
        $xor_seq = { FE 0C 0E 00 20 [4] 5A 20 [4] 61 } 

    condition:
        all of them and #xor_seq > 10
}
```

## Sample Hashes
```
852532c0cafdb2d624b48749193f3c378d0536e7172cb1c04717b05e567b3235
3ea6abaca7ea51313aa5e377d99f3e391c7751614d39d5001bbfdb82bbcf1e40
a3a84294c37b9201499bda040b70abb8c940fa4481df0c84dc59d5c0fc632938
e354e63c4e25e8e2aab729887083154ffa32e7cc55a745365b08efb3a1a4fee6
26196e4d9df06630d29b0d5214d7d2de545adfe2b282f5ea054ce35ae35e4dd2
25961b30ec2cce43e4bf8404e1f4001b8063bcacaecc1e4c2bcf4f216dc9edc9
25961b30ec2cce43e4bf8404e1f4001b8063bcacaecc1e4c2bcf4f216dc9edc9
ba2690ebff7c660724fd94e36b2a4320035c08003aa954d3fe3b6745a6b6d52f
ba2690ebff7c660724fd94e36b2a4320035c08003aa954d3fe3b6745a6b6d52f
b75f04b2ea1454088f26af1fac71badf8c4443ca4c4db0c7cf8b1775af47e567
4023bf1b700e03fc7ea689ef4d596dbe29dc8634c81c15b41a1929a2bf923dc0
717f605727d21a930737e9f649d8cf5d12dbd1991531eaf68bb58990d3f57c05
566af59702210f1302efb94acf4efcce7fea211eb4ca0db44e77315ea27dcbab
cdc6c72044c7b495ec1cf2017ef661ae780460cbabe288d54a56355980ac5eb3
14775bf4fe92e8f313d31e9e83ec49429afc7dd90368e60d1c6e879efcf83478
0ed700cdee0bf51803bfe1b97605da74fbf20c02def3a835200fa751355a8c2d
c898ea5531f1e66fdff14a58b9548843edfee323568136d12309cb73ad49488f
a259ded5931e4dbf664b0df57987a30329eda282d19ae27c78234d9aaa0f85e6
827077e983c6f155f573f4418c58824e7775d264e8307f7f4541d94c7862bc60
a802de8152216cb09c2a3840e96e271e27a4ac04fd5be2a77cf6b0a082d32672
0793e016deb35ff9cad2e75ffe3c79ac2e9f4a63f48760e198435abd1244281d
d0d1497a95010e7bf76054da5a797b83667b92ea897e4f0b019a498e554dcd55
4e996b2d56134bd9c000936e973fa7666c21e610c591ae224b34992c443a8e5e
48b5edc78601f342221dd42e12275b626eb44e1944ecc744d97c29daef0cdbc2
2eafab46d4d43c7fa25e24104a82cd80afb6b059332e62e911b2f3879dbc98bd
```

## Sample C2 
***NOTE: Many of the recent payloads use SMTP credentials for data exfil, not captured here as they must be manually parsed***
```
checkip.amazonaws.com
checkip.dyndns.com
```
