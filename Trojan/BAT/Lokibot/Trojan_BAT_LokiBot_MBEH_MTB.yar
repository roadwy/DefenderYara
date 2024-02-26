
rule Trojan_BAT_LokiBot_MBEH_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.MBEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 08 8e 69 5d 13 07 09 11 06 6f 90 01 01 00 00 0a 5d 13 0b 08 11 07 91 13 0c 11 06 11 0b 6f 90 01 01 00 00 0a 13 0d 02 08 09 28 90 01 01 00 00 06 13 0e 02 11 0c 11 0d 11 0e 28 90 01 01 00 00 06 13 0f 08 11 07 11 0f 20 00 01 00 00 5d d2 9c 09 17 59 0d 09 16 2f b0 90 00 } //01 00 
		$a_01_1 = {53 75 64 6f 6b 75 2e 50 72 6f 70 65 72 74 69 65 } //00 00  Sudoku.Propertie
	condition:
		any of ($a_*)
 
}