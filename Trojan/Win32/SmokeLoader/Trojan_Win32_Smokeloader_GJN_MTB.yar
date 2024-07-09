
rule Trojan_Win32_Smokeloader_GJN_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 ?? 8d 3c 33 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24 } //10
		$a_03_1 = {33 cf 33 c1 2b e8 81 c3 ?? ?? ?? ?? ff 4c 24 ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}