
rule Trojan_BAT_Formbook_RDV_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 11 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0b 07 11 09 11 08 6a 5d d4 11 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}