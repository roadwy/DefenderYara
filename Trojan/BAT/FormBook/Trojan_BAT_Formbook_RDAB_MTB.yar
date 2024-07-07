
rule Trojan_BAT_Formbook_RDAB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 08 11 08 61 11 07 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 09 06 07 11 09 d2 9c 07 17 58 0b 08 17 58 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}