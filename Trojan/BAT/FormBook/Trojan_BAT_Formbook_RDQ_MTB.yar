
rule Trojan_BAT_Formbook_RDQ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0b d4 91 61 28 90 01 04 07 11 09 08 6a 5d d4 91 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}