
rule Trojan_Win32_Smokeloader_MBJB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.MBJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 14 24 b8 d1 05 00 00 01 04 24 8b 04 24 8a 0c 30 8b 15 90 01 04 88 0c 32 90 00 } //01 00 
		$a_01_1 = {33 c0 33 c9 8d 54 24 14 66 89 44 24 04 89 44 24 06 89 44 24 0a } //01 00 
		$a_01_2 = {65 00 66 00 69 00 74 00 6f 00 74 00 69 00 20 00 6d 00 61 00 78 00 61 00 78 } //00 00 
	condition:
		any of ($a_*)
 
}