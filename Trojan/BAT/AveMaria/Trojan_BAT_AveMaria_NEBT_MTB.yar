
rule Trojan_BAT_AveMaria_NEBT_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 08 09 11 04 28 ?? 00 00 06 28 ?? 00 00 06 00 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 00 07 06 28 ?? 00 00 06 d2 6f ?? 00 00 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d c0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}