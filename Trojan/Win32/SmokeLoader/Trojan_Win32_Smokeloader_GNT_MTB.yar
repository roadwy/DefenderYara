
rule Trojan_Win32_Smokeloader_GNT_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 f5 33 c6 2b f8 81 c3 ?? ?? ?? ?? ff 4c 24 ?? 89 44 24 } //10
		$a_03_1 = {8b c7 c1 e8 ?? 03 44 24 ?? 8d 14 3b 33 ca 89 44 24 ?? 89 4c 24 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}