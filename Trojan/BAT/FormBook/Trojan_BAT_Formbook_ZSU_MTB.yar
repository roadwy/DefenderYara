
rule Trojan_BAT_Formbook_ZSU_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZSU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 11 07 6f ?? 00 00 0a 03 11 07 17 da 6f ?? 00 00 0a 28 ?? 00 00 0a 03 11 07 17 da 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 08 08 11 08 6f ?? 00 00 0a 00 11 07 17 d6 13 07 11 07 11 06 31 be } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}