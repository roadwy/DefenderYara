
rule Trojan_BAT_AveMaria_NEBQ_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {5a 57 4d 32 4d 7a 4a 6d 5a 44 6b 74 4d 54 59 35 4e 43 30 30 5a 6a 52 68 4c 54 6c 69 5a 6d 59 74 5a 6a 49 77 4e 6a 41 77 5a 54 4d 33 4f 54 67 78 } //05 00 
		$a_01_1 = {53 00 45 00 5a 00 4c 00 53 00 6b 00 74 00 48 00 53 00 6b 00 67 00 6b 00 } //05 00 
		$a_01_2 = {48 46 4b 4a 4b 47 4a 48 2e 65 78 65 } //02 00 
		$a_01_3 = {70 62 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //02 00 
		$a_01_4 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}