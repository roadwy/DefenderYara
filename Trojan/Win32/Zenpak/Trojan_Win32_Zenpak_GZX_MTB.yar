
rule Trojan_Win32_Zenpak_GZX_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d0 83 c2 03 89 e8 50 8f 05 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 89 30 29 c2 ba 04 00 00 00 01 3d ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 01 18 b9 02 00 00 00 e2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Zenpak_GZX_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e0 50 8f 05 ?? ?? ?? ?? 48 b9 02 00 00 00 ?? ?? 31 3d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 04 00 00 00 89 c2 31 35 ?? ?? ?? ?? 31 2d ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 ?? 55 89 e5 b8 01 00 00 00 5d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Zenpak_GZX_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 00 ca d6 41 00 f4 d6 41 00 4f d7 41 00 c6 d7 41 00 fc d7 41 00 46 d8 } //5
		$a_03_1 = {b5 07 41 00 79 07 41 00 b5 ?? ?? ?? ?? 07 41 00 b5 ?? ?? ?? ?? 07 41 00 79 07 41 00 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 10 83 ec 08 56 8b f0 c1 e8 1d } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}