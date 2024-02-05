
rule Trojan_BAT_AveMaria_NEBC_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {14 16 9a 26 16 2d f9 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 39 90 01 02 00 00 90 00 } //05 00 
		$a_03_1 = {d0 01 00 00 1b 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 11 05 28 90 01 01 00 00 0a 13 06 90 00 } //05 00 
		$a_03_2 = {00 00 0a 7e 01 00 00 04 02 1a 58 08 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a a5 01 00 00 1b 0b 11 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}