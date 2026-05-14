
rule Trojan_BAT_Formbook_ZGI_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 2d 1c 02 08 09 6f ?? 00 00 0a 13 05 07 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 17 13 04 2b a6 11 04 17 33 12 07 12 05 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}