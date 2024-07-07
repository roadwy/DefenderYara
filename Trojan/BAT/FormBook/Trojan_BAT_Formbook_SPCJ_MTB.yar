
rule Trojan_BAT_Formbook_SPCJ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.SPCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 8e 69 6a 5d d4 91 61 28 90 01 03 0a 07 11 05 17 6a 58 07 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}