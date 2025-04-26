
rule Trojan_Win32_Smokeloader_GKA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 cb 33 c1 2b e8 81 c7 ?? ?? ?? ?? ff 4c 24 18 } //10
		$a_03_1 = {8d 1c 37 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}