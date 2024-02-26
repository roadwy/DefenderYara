
rule Trojan_BAT_Barys_NL_MTB{
	meta:
		description = "Trojan:BAT/Barys.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {26 20 16 00 00 00 38 07 90 01 03 11 44 02 58 20 e2 90 01 03 11 00 59 11 01 61 61 11 0c 20 93 90 01 03 11 00 58 11 01 58 5f 61 13 41 90 00 } //01 00 
		$a_03_1 = {11 1e 8e 69 13 27 20 0e 00 00 00 38 2a 90 01 03 11 1e 11 09 11 25 11 23 61 19 11 1d 58 61 11 2b 61 d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Barys_NL_MTB_2{
	meta:
		description = "Trojan:BAT/Barys.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 07 11 02 1a 62 11 02 1b 63 61 11 02 58 11 03 11 00 11 03 19 5f 94 58 61 58 13 07 20 0a 00 00 00 38 e5 fd ff ff } //01 00 
		$a_03_1 = {11 07 02 58 11 00 20 22 90 01 03 58 11 01 59 61 11 0c 20 63 90 01 03 11 00 59 11 01 58 5f 61 13 41 20 4f 00 00 00 38 68 e6 ff ff 17 11 09 5f 3a b9 ff ff ff 90 00 } //01 00 
		$a_01_2 = {11 1f 11 09 11 24 11 27 61 19 11 18 58 61 11 2f 61 d2 9c 20 05 00 00 00 7e 54 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}