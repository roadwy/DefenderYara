
rule Trojan_BAT_AveMaria_NEAS_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f 90 01 01 00 00 0a 08 17 58 0c 08 02 8e 69 32 e4 90 00 } //04 00 
		$a_03_1 = {7b 01 00 00 04 28 03 00 00 06 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}