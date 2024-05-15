
rule Trojan_BAT_Formbook_RDR_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 10 d4 91 61 07 11 0e 11 0c 6a 5d d4 91 } //00 00 
	condition:
		any of ($a_*)
 
}