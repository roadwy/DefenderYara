
rule Trojan_BAT_AveMaria_MBGL_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.MBGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0d 2b 29 11 07 06 08 58 07 09 58 6f 90 01 01 00 00 0a 13 0f 12 0f 28 90 01 01 00 00 0a 13 09 11 05 11 04 11 09 9c 11 04 17 58 13 04 09 17 58 0d 09 17 fe 04 13 0a 11 0a 2d cd 90 00 } //01 00 
		$a_03_1 = {13 06 16 13 04 20 01 5c 00 00 8d 90 01 01 00 00 01 13 05 11 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}