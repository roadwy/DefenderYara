
rule Trojan_BAT_Formbook_PGFH_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PGFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 06 7b 89 00 00 04 6f ?? 00 00 0a 13 05 03 07 6f ?? 00 00 0a 59 13 06 11 05 28 ?? 00 00 06 13 07 07 11 07 16 91 6f ?? 00 00 0a 00 11 06 17 59 25 13 06 16 fe 02 16 fe 01 13 0e 11 0e 2c 05 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}