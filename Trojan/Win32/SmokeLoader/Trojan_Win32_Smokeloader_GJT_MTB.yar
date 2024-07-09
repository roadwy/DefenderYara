
rule Trojan_Win32_Smokeloader_GJT_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c7 33 c1 2b f0 89 44 24 ?? 8b c6 c1 e0 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8d 3c 2e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GJT_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d6 31 54 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 15 } //10
		$a_03_1 = {8b c7 c1 e8 ?? 8d 34 3b c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}