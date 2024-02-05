
rule Trojan_BAT_SpyNoon_ASP_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ASP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {1b 2d 16 26 2b 3d 16 2b 3d 8e 69 16 2c 0e 26 26 26 2b 36 2b 0e 2b 35 2b da 0b 2b e8 28 90 01 03 0a 2b ee 2a 28 90 01 03 06 2b c4 28 90 01 03 0a 2b c3 06 2b c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpyNoon_ASP_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.ASP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {15 6a 16 28 90 01 03 0a 17 8d 3c 00 00 01 0b 07 16 17 9e 07 28 90 01 03 0a 02 02 7b 12 00 00 04 72 fb 00 00 70 15 16 28 90 01 03 0a 7d 11 00 00 04 02 6f 90 01 03 06 02 7b 11 00 00 04 17 9a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpyNoon_ASP_MTB_3{
	meta:
		description = "Trojan:BAT/SpyNoon.ASP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 14 fe 01 13 05 11 05 2c 11 72 c3 00 00 70 06 28 90 01 03 0a 73 2c 00 00 0a 7a 09 07 6f 90 01 03 0a 13 04 11 04 14 fe 01 13 06 11 06 2c 11 72 e9 00 00 70 07 28 90 01 03 0a 73 2e 00 00 0a 7a 11 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}