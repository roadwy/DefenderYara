
rule Trojan_BAT_AveMaria_NEAO_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 09 11 04 28 3b 00 00 06 13 05 08 09 11 04 6f 8d 00 00 0a 13 06 11 06 28 8e 00 00 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 08 11 08 2d c8 } //00 00 
	condition:
		any of ($a_*)
 
}