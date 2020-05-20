# AVE MARIA (AKA AveMariaRAT or Warzone RAT)
* _Note: Some consider Warzone RAT separate from AVE MARIA; I am choosing to include both in one ruleset due to their similarities until given sufficient reason to break them up._

## Reporting
* https://malpedia.caad.fkie.fraunhofer.de/details/win.ave_maria
* https://blog.team-cymru.com/2019/07/25/unmasking-ave_maria/
* https://yoroi.company/research/the-ave_maria-malware/

## YARA
```yara
rule ave_maria_warzone_rat {
  meta:
    author = "jeFF0Falltrades"
    ref = "https://blog.team-cymru.com/2019/07/25/unmasking-ave_maria/"

  strings:
    $str_0 = "5.206.225.104/dll/" wide ascii
    $str_1 = "AVE_MARIA" wide ascii 
    $str_2 = "MortyCrypter\\MsgBox.exe" wide ascii 
    $str_3 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q" wide ascii 
    $str_4 = "ellocnak.xml" wide ascii 
    $str_5 = "Hey I'm Admin" wide ascii 
    $str_6 = "AWM_FIND" wide ascii 
    $str_7 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide ascii 
    $str_8 = "warzone" wide ascii 

  condition:
  	3 of them
}
```

## Sample Hashes
```
81043261988c8d85ca005f23c14cf098552960ae4899fc95f54bcae6c5cb35f1
1220012ee42e839b93697d0ded0a1d09f9d2844253915c77d9f02690bf57c3f4
531d967b9204291e70e3aab161a5b7f1001339311ece4f2eed8e52e91559c755 
a03764da06bbf52678d65500fa266609d45b972709b3213a8f83f52347524cf2 
263433966d28f1e6e5f6ae389ca3694495dd8fcc08758ea113dddc45fe6b3741
...and so, so many more
```
