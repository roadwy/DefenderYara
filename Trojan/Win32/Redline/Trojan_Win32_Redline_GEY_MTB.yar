
rule Trojan_Win32_Redline_GEY_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 e0 03 8a 98 90 01 04 32 9e 90 01 04 e8 90 01 04 8b f8 8b 0f 8b 49 04 8b 4c 39 30 8b 49 04 89 4c 24 14 8b 11 90 00 } //01 00 
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}