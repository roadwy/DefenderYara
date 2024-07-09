
rule Trojan_Win32_Zenpak_RB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 20 29 c2 4a e8 21 00 00 00 c3 31 c2 01 c2 42 31 1d ?? ?? ?? ?? b8 06 00 00 00 8d 05 ?? ?? ?? ?? 01 30 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e1 c7 41 08 00 00 00 00 c7 41 04 41 01 00 00 c7 01 c7 b6 ?? 00 8b 0d ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? ff d1 83 ec 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_RB_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 f0 5c 00 00 00 89 d7 01 f7 81 c7 34 00 00 00 8b 37 69 f8 5c 00 00 00 01 fa 81 c2 30 00 00 00 0f b7 12 31 f2 01 ca 05 01 00 00 00 3d 27 03 00 00 89 d1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}