
rule Trojan_BAT_Formbook_RDT_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 07 11 06 17 6a 58 07 8e 69 6a 5d d4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}