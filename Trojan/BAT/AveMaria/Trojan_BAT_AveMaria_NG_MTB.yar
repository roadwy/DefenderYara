
rule Trojan_BAT_AveMaria_NG_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 0b 00 00 06 0a 28 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 75 90 01 01 00 00 1b 0b 07 16 07 8e 69 28 90 01 01 00 00 0a 07 2a 90 00 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 33 39 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_2 = {42 61 7a 73 69 65 78 } //00 00 
	condition:
		any of ($a_*)
 
}