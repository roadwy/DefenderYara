
rule Trojan_BAT_AveMaria_NEAU_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 05 08 6f 90 01 01 00 00 0a 09 20 00 01 00 00 14 14 11 06 74 02 00 00 1b 6f 90 01 01 00 00 0a 90 00 } //05 00 
		$a_03_1 = {1a 8d 15 00 00 01 25 16 11 04 a2 25 17 7e 90 01 01 00 00 0a a2 25 18 07 a2 25 19 17 8c 04 00 00 01 a2 13 06 90 00 } //01 00 
		$a_01_2 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 2e 30 2b 34 34 37 33 34 31 39 36 34 66 } //00 00 
	condition:
		any of ($a_*)
 
}