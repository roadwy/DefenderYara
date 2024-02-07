
rule Trojan_BAT_AveMariaRat_MN_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRat.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 16 0d 2b 1a 00 07 90 0a 1f 00 28 90 01 03 0a 0a 20 00 58 00 00 8d 46 00 00 01 90 02 09 09 06 09 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 00 09 17 58 0d 09 20 00 58 00 00 fe 04 13 04 11 04 2d 90 00 } //01 00 
		$a_01_1 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_01_2 = {47 65 74 50 6c 61 63 65 64 47 65 6d 73 53 74 72 69 6e 67 } //01 00  GetPlacedGemsString
		$a_01_3 = {57 00 65 00 6c 00 63 00 6f 00 6d 00 65 00 20 00 74 00 6f 00 20 00 47 00 68 00 6f 00 73 00 74 00 20 00 50 00 61 00 72 00 74 00 79 00 } //01 00  Welcome to Ghost Party
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_5 = {42 63 65 6c 6c 65 72 6d 30 33 } //01 00  Bcellerm03
		$a_01_6 = {44 65 62 75 67 } //00 00  Debug
	condition:
		any of ($a_*)
 
}