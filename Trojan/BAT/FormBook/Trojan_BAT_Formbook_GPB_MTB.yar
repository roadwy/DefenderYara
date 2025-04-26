
rule Trojan_BAT_Formbook_GPB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 da 0c 16 0d 2b 17 07 09 07 09 6f ?? 00 00 0a 1f 33 61 b4 6f 94 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}