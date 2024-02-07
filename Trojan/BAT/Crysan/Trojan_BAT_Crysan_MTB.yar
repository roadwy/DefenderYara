
rule Trojan_BAT_Crysan_MTB{
	meta:
		description = "Trojan:BAT/Crysan!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 06 0b 16 8d 4c 90 01 02 01 0c 07 7e 36 90 01 02 04 25 2d 17 26 7e 35 90 01 02 04 fe 06 90 01 03 06 73 5f 90 01 02 0a 25 80 36 90 01 02 04 28 01 90 01 02 2b 28 02 90 01 02 2b 0c 90 00 } //01 00 
		$a_01_1 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_2 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //01 00  get_Assembly
		$a_01_3 = {44 69 72 65 63 74 6f 72 79 45 6e 74 72 79 } //00 00  DirectoryEntry
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Crysan_MTB_2{
	meta:
		description = "Trojan:BAT/Crysan!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 06 00 "
		
	strings :
		$a_03_0 = {07 16 fe 01 0d 09 2c 14 06 07 07 b4 9c 06 07 17 d6 03 28 b7 90 01 02 0a b4 9c 00 2b 18 07 17 fe 02 13 04 11 04 2c 0e 06 07 03 1f 63 d6 28 b7 90 01 02 0a b4 9c 90 00 } //01 00 
		$a_01_1 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } //01 00  GetResourceString
		$a_01_2 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_01_3 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_4 = {54 6f 49 6e 74 65 67 65 72 } //00 00  ToInteger
	condition:
		any of ($a_*)
 
}