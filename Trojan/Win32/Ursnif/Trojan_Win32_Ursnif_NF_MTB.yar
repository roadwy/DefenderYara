
rule Trojan_Win32_Ursnif_NF_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {c7 85 e0 fe ff ff 00 00 00 00 8b 95 60 ff ff ff 89 95 08 ff ff ff 8d 85 6c ff ff ff 50 8b 8d 08 ff ff ff 8b 11 8b 85 08 ff ff ff 50 ff 52 50 } //2
		$a_01_1 = {c7 85 dc fe ff ff 00 00 00 00 8b 85 6c ff ff ff 89 85 ec fe ff ff c7 85 6c ff ff ff 00 00 00 00 8b 8d ec fe ff ff 89 8d 58 ff ff ff c7 85 50 ff ff ff 08 00 00 00 8d 95 50 ff ff ff 8d 4d d0 } //1
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_3 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 } //1 taskkill /f /im
		$a_01_4 = {2f 00 63 00 20 00 64 00 65 00 6c 00 } //1 /c del
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}