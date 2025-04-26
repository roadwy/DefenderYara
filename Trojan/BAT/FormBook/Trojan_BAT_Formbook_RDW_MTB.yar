
rule Trojan_BAT_Formbook_RDW_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 5d 13 07 07 11 07 91 08 11 06 1f 16 5d 91 61 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}