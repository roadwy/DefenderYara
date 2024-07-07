
rule Trojan_Win32_Smokeloader_GJH_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c6 33 c1 2b f8 89 44 24 90 01 01 8b c7 c1 e0 90 01 01 81 3d 90 01 08 89 44 24 90 00 } //10
		$a_03_1 = {8b cf c1 e9 90 01 01 03 f7 c7 05 90 01 04 19 36 6b ff c7 05 90 01 08 89 4c 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}