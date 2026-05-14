
rule Trojan_BAT_Formbook_ABM_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 09 11 04 6f ?? 00 00 0a 13 07 16 13 08 00 11 08 7e ?? 00 00 04 16 94 1f 51 61 2f 13 11 06 06 6f ?? 00 00 0a 03 6f ?? 00 00 0a 16 fe 01 2b 01 17 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}