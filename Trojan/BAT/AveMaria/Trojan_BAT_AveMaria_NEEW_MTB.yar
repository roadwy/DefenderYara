
rule Trojan_BAT_AveMaria_NEEW_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {00 28 0e 00 00 06 0a 28 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0b de 03 26 de d9 07 2a 90 00 } //02 00 
		$a_01_1 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //02 00 
		$a_01_2 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //02 00 
		$a_01_3 = {52 65 76 65 72 73 65 } //02 00 
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}