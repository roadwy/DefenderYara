
rule Trojan_BAT_Formbook_ZPG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 03 11 04 6f ?? 00 00 0a 13 06 12 06 28 ?? 00 00 0a 13 07 12 06 28 ?? 00 00 0a 13 08 12 06 28 ?? 00 00 0a 13 09 11 07 28 ?? 00 00 06 13 07 11 08 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}