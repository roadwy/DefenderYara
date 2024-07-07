
rule Trojan_BAT_Formbook_AMAB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 07 8e 69 5d 13 05 11 04 08 6f 90 01 01 00 00 0a 5d 13 06 07 11 05 91 13 07 08 11 06 6f 90 01 01 00 00 0a 13 08 02 07 11 04 28 90 01 01 00 00 06 13 09 02 11 07 11 08 11 09 28 90 01 01 00 00 06 13 0a 07 11 05 02 11 0a 28 90 01 01 00 00 06 9c 11 04 17 59 13 04 11 04 16 2f ad 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}