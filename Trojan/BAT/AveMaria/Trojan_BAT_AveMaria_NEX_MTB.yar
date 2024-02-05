
rule Trojan_BAT_AveMaria_NEX_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 7e 6f 00 00 04 28 a7 00 00 0a 0a 17 72 b5 14 00 70 28 4c 00 00 06 0b 73 a8 00 00 0a 0c 08 1f 10 07 28 4b 00 00 06 74 07 00 00 1b 6f a9 00 00 0a 00 08 1f 10 07 28 4b 00 00 06 74 07 00 00 1b 6f aa 00 00 0a 00 08 } //01 00 
		$a_01_1 = {35 00 37 00 48 00 33 00 46 00 4e 00 50 00 43 00 35 00 34 00 4a 00 48 00 58 00 46 00 46 00 46 00 38 00 44 00 43 00 33 00 34 00 37 00 } //00 00 
	condition:
		any of ($a_*)
 
}