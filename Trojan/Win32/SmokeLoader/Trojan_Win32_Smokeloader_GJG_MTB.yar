
rule Trojan_Win32_Smokeloader_GJG_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GJG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 90 01 01 8d 34 2b c7 05 90 01 04 19 36 6b ff c7 05 90 01 08 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 81 3d 90 00 } //0a 00 
		$a_03_1 = {33 c6 33 c1 2b d8 89 44 24 90 01 01 8b c3 c1 e0 90 01 01 81 3d 90 01 08 89 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}