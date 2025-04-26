
rule Trojan_BAT_Formbook_OKA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.OKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 11 06 9e 11 04 11 07 95 11 04 11 05 95 58 20 ff 00 00 00 5f 13 13 11 04 11 13 95 d2 13 14 09 11 12 07 11 12 91 11 14 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}