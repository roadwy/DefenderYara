
rule Trojan_BAT_AveMaria_NEEU_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 22 00 06 6f 90 01 01 00 00 0a 07 9a 6f 90 01 01 00 00 0a 14 14 6f 90 01 01 00 00 0a 2c 02 de 0e de 03 26 de 00 07 17 58 0b 07 90 00 } //01 00 
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //01 00 
		$a_01_2 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //01 00 
		$a_01_3 = {53 79 73 74 65 6d 2e 4e 65 74 2e 48 74 74 70 } //01 00 
		$a_01_4 = {49 6e 76 6f 6b 65 } //00 00 
	condition:
		any of ($a_*)
 
}