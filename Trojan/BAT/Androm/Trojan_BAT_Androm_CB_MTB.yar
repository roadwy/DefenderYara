
rule Trojan_BAT_Androm_CB_MTB{
	meta:
		description = "Trojan:BAT/Androm.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {13 04 08 13 05 11 04 13 06 11 06 14 fe 03 13 07 11 07 2c 0b 11 06 6f 38 00 00 06 0b 00 2b 04 00 14 0b 00 11 05 07 } //01 00 
		$a_01_1 = {50 6f 6e 74 6f 6f 6e 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Pontoon.Resources
		$a_01_2 = {41 66 66 69 63 68 65 72 49 6e 67 72 65 64 69 65 6e 74 73 } //01 00  AfficherIngredients
		$a_01_3 = {50 6f 6e 74 6f 6f 6e 2e 50 69 7a 7a 61 32 } //00 00  Pontoon.Pizza2
	condition:
		any of ($a_*)
 
}