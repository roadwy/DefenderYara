
rule Trojan_Win32_Smokeloader_GJS_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 d7 33 c2 2b d8 81 f9 90 01 06 81 c5 90 01 04 ff 4c 24 90 01 01 0f 85 90 00 } //0a 00 
		$a_03_1 = {8b ce c1 e9 90 01 01 8d 3c 2e c7 05 90 01 04 19 36 6b ff c7 05 90 01 08 89 4c 24 90 01 01 8b 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}