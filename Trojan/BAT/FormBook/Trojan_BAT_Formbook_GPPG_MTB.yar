
rule Trojan_BAT_Formbook_GPPG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.GPPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 58 0f 00 28 ?? 00 00 0a 58 6c 23 00 00 00 00 00 e8 87 40 5b 23 00 00 00 00 00 00 59 40 5a 0b } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}