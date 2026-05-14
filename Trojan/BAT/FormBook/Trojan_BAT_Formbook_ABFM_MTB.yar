
rule Trojan_BAT_Formbook_ABFM_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ABFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 08 11 09 6f ?? 00 00 0a 13 0c 11 04 09 12 0c 28 ?? 00 00 0a 9c 09 17 58 0d 06 17 58 0a 06 08 11 06 5a fe 04 13 0a 11 0a 2d ca } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}