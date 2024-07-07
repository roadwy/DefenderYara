
rule Trojan_BAT_Formbook_NYF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 d4 02 fc c9 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 90 01 01 00 00 00 16 00 00 00 57 00 00 00 74 00 00 00 90 01 01 00 00 00 90 01 01 00 00 00 01 00 00 00 03 00 00 00 17 00 00 00 01 00 00 00 02 00 00 00 02 00 00 00 02 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}