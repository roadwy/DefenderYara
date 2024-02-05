
rule Trojan_BAT_AveMaria_NEFD_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 16 09 16 1e 28 90 01 01 00 00 0a 00 07 09 6f 90 01 01 00 00 0a 00 07 18 6f 90 01 01 00 00 0a 00 07 6f 90 01 01 00 00 0a 03 16 03 8e 69 6f 90 01 01 00 00 0a 13 05 11 05 0a 2b 00 06 2a 90 00 } //02 00 
		$a_01_1 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 } //02 00 
		$a_01_2 = {73 65 74 5f 57 69 6e 64 6f 77 53 74 79 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}