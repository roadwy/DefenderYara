
rule Trojan_BAT_RevengeRat_ARV_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.ARV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 12 02 1f 64 14 0d 12 03 1f 64 28 90 01 03 06 2c 08 72 90 01 03 70 0a de 1c 07 17 90 01 01 0b 07 1a 31 d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_RevengeRat_ARV_MTB_2{
	meta:
		description = "Trojan:BAT/RevengeRat.ARV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 1b 08 68 07 1f 64 06 1f 64 28 90 01 03 06 2c 08 72 90 01 03 70 0d de 13 08 17 58 0c 08 1a 31 e1 90 00 } //01 00 
		$a_03_1 = {0a 14 0b 16 0c 16 0d 16 13 04 14 13 05 16 13 06 06 07 08 12 06 12 03 12 04 11 05 16 28 90 01 01 00 00 06 26 11 06 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_RevengeRat_ARV_MTB_3{
	meta:
		description = "Trojan:BAT/RevengeRat.ARV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {7e 7b 00 00 04 08 7e 79 00 00 04 06 7e 75 00 00 04 08 28 90 01 03 06 1e 5b 28 90 01 03 06 16 2c 79 26 26 26 7e 7d 00 00 04 08 7e 79 00 00 04 06 7e 77 00 00 04 08 28 90 00 } //01 00 
		$a_01_1 = {57 00 69 00 6e 00 57 00 6f 00 72 00 64 00 2e 00 65 00 78 00 65 00 } //00 00  WinWord.exe
	condition:
		any of ($a_*)
 
}