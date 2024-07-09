
rule Trojan_Win32_Smokeloader_GNR_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 ?? 03 44 24 ?? 03 d5 33 c2 8b 54 24 ?? 03 d1 33 c2 2b f0 89 44 24 ?? 8b c6 c1 e0 } //10
		$a_03_1 = {8b d6 c1 ea ?? c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Smokeloader_GNR_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 ?? 03 44 24 ?? 03 d5 33 c2 8b 54 24 ?? 03 d1 33 c2 2b f0 89 44 24 ?? 8b c6 c1 e0 ?? 89 1d ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 7c 24 ?? 03 fe 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}