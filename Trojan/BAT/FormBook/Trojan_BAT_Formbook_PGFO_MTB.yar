
rule Trojan_BAT_Formbook_PGFO_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PGFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 09 6f ?? 00 00 0a 13 04 03 07 6f ?? 00 00 0a 59 13 05 19 8d ?? 00 00 01 25 16 12 04 28 ?? 00 00 0a 9c 25 17 12 04 28 ?? 00 00 0a 9c 25 18 12 04 28 ?? 00 00 0a 9c 06 7b ?? 00 00 04 25 2d 18 26 06 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}