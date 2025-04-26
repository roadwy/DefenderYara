
rule Trojan_BAT_Formbook_PAEK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PAEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 05 11 06 09 11 06 11 04 95 9e 11 06 11 04 11 05 9e 07 11 0e d4 91 13 0f 11 06 09 95 11 06 11 04 95 58 d2 13 10 11 10 20 ff 00 00 00 5f d2 13 11 11 06 11 11 95 d2 13 12 11 07 11 0e d4 11 0f 6e 11 12 20 ff 00 00 00 5f 6a 61 d2 9c 00 11 0e 17 6a 58 13 0e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}