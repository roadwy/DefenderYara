
rule Trojan_Win32_Smokeloader_GJN_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 90 01 01 8d 3c 33 c7 05 90 01 04 19 36 6b ff c7 05 90 01 08 89 4c 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 00 } //0a 00 
		$a_03_1 = {33 cf 33 c1 2b e8 81 c3 90 01 04 ff 4c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}