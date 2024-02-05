
rule Trojan_BAT_AveMaria_NMA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 18 20 a2 e7 3f 61 5a 20 90 01 03 a8 61 38 90 01 03 ff 7e 90 01 03 04 7e 90 01 03 04 28 90 01 03 06 20 90 01 03 09 38 90 01 03 ff 11 17 17 58 13 17 20 90 01 03 7e 90 00 } //01 00 
		$a_01_1 = {42 48 4e 68 37 37 32 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AveMaria_NMA_MTB_2{
	meta:
		description = "Trojan:BAT/AveMaria.NMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 11 06 20 90 01 03 cd 5a 20 90 01 03 34 61 38 90 01 03 ff 02 7b 90 01 03 04 20 90 01 03 18 28 90 01 03 2b 28 90 01 03 06 90 00 } //01 00 
		$a_01_1 = {43 43 30 31 2e 66 72 6d 44 61 6e 68 53 61 63 68 53 61 6e 50 68 61 6d 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}