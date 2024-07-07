
rule Trojan_Win32_Smokeloader_GJL_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d7 33 c2 89 44 24 90 01 01 2b d8 8b 44 24 90 01 01 29 44 24 90 01 01 ff 4c 24 90 00 } //10
		$a_03_1 = {8b c6 c1 e8 90 01 01 03 fe c7 05 90 01 04 19 36 6b ff c7 05 90 01 08 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}