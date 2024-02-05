
rule Trojan_BAT_AveMaria_NEBX_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {25 26 25 1f 1c 28 90 01 01 00 00 06 20 82 00 00 00 28 90 01 01 00 00 06 90 00 } //05 00 
		$a_03_1 = {a2 25 1f 24 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 25 26 a2 25 1f 28 90 00 } //02 00 
		$a_01_2 = {5a 57 4d 32 4d 7a 4a 6d 5a 44 6b 74 4d 54 59 35 4e 43 30 30 5a 6a 52 68 4c 54 6c 69 5a 6d 59 74 5a 6a 49 77 4e 6a 41 77 5a 54 4d 33 4f 54 67 78 } //00 00 
	condition:
		any of ($a_*)
 
}