
rule Trojan_Win32_Zloader_ZX{
	meta:
		description = "Trojan:Win32/Zloader.ZX,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {55 89 e5 56 8b 75 08 85 f6 74 [0-10] 6a 00 e8 ?? ?? ?? ?? 83 c4 08 56 6a 00 ff 35 ?? ?? ?? ?? ff d0 5e 5d c3 } //100
		$a_03_2 = {55 89 e5 53 57 56 8b 7d 08 85 ff 74 [0-1e] 6a 00 e8 ?? ?? ?? ?? 83 c4 08 8b 1d [0-16] 50 53 ff ?? eb 02 31 c0 5e 5f 5b 5d c3 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100+(#a_03_2  & 1)*100) >=201
 
}