
rule Trojan_BAT_Formbook_AMAR_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 58 08 5d 91 [0-1e] 08 5d 08 58 08 5d 91 [0-05] 61 [0-1e] 20 00 01 00 00 5d [0-09] 20 00 01 00 00 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}