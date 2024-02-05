
rule Trojan_BAT_AveMaria_NEBB_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 1c 74 0c 00 00 1b 28 2d 01 00 06 11 1e 18 d6 5d 6f 79 00 00 0a 11 1e 17 d6 13 1e 11 1e 1f 0a 31 de } //02 00 
		$a_01_1 = {78 00 63 00 76 00 78 00 76 00 65 00 67 00 65 00 74 00 32 00 31 00 71 00 } //02 00 
		$a_01_2 = {56 00 43 00 58 00 4d 00 55 00 39 00 39 00 } //02 00 
		$a_01_3 = {7b 00 30 00 7d 00 3a 00 2f 00 2f 00 7b 00 31 00 7d 00 2e 00 7b 00 32 00 7d 00 2e 00 7b 00 33 00 7d 00 } //00 00 
	condition:
		any of ($a_*)
 
}