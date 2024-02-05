
rule Trojan_BAT_AveMaria_NEV_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 0e 02 00 0a 0c 08 07 1f 10 6f 0f 02 00 0a 6f 10 02 00 0a 00 08 07 1f 10 6f 0f 02 00 0a 6f 11 02 00 0a 00 08 6f 12 02 00 0a } //01 00 
		$a_01_1 = {35 00 34 00 35 00 42 00 47 00 47 00 50 00 37 00 39 00 54 00 50 00 35 00 4e 00 44 00 38 00 37 00 47 00 35 00 58 00 51 00 38 00 38 00 } //01 00 
		$a_01_2 = {41 00 69 00 6e 00 74 00 61 00 63 00 } //00 00 
	condition:
		any of ($a_*)
 
}