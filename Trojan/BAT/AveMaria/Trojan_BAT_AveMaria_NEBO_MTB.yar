
rule Trojan_BAT_AveMaria_NEBO_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {00 07 08 09 28 15 00 00 06 28 13 00 00 06 00 28 12 00 00 06 28 14 00 00 06 28 11 00 00 06 00 7e 04 00 00 04 06 28 10 00 00 06 d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 } //00 00 
	condition:
		any of ($a_*)
 
}