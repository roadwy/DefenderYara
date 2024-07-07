
rule Trojan_BAT_Formbook_RDU_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 10 d4 91 61 06 11 0f 11 08 6a 5d d4 91 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}