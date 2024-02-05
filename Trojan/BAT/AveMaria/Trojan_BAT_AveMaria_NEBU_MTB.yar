
rule Trojan_BAT_AveMaria_NEBU_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {28 37 00 00 0a 06 6f 36 00 00 0a 25 26 0c 1f 61 6a 08 28 8f 00 00 06 25 26 } //03 00 
		$a_01_1 = {5a 57 4d 32 4d 7a 4a 6d 5a 44 6b 74 4d 54 59 35 4e 43 30 30 5a 6a 52 68 4c 54 6c 69 5a 6d 59 74 5a 6a 49 77 4e 6a 41 77 5a 54 4d 33 4f 54 67 78 } //03 00 
		$a_01_2 = {4c 6f 67 69 63 4e 50 20 53 6f 66 74 77 61 72 65 20 32 30 30 39 } //01 00 
		$a_01_3 = {50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 79 6c 65 } //01 00 
		$a_01_4 = {53 6c 65 65 70 } //00 00 
	condition:
		any of ($a_*)
 
}