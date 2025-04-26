
rule Trojan_BAT_AveMaria_NEBE_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 09 11 04 28 57 00 00 06 28 55 00 00 06 00 28 54 00 00 06 28 56 00 00 06 28 53 00 00 06 00 07 06 28 52 00 00 06 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d c5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}