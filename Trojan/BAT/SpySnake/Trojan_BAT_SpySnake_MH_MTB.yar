
rule Trojan_BAT_SpySnake_MH_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 11 09 07 11 09 9a 1f 10 28 90 01 03 0a 9c 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MH_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 54 79 70 65 73 } //01 00 
		$a_01_1 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_81_2 = {44 54 54 2e 65 78 65 } //01 00 
		$a_81_3 = {47 61 6d 65 57 69 6e 64 6f 77 } //01 00 
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_5 = {4f 74 68 65 6c 6c 6f 57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e } //01 00 
		$a_03_6 = {19 8d 0a 00 00 01 25 16 72 17 00 00 70 a2 25 17 72 5d 00 00 70 a2 25 18 07 06 28 90 01 03 06 a2 0c 20 05 00 00 00 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}