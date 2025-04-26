
rule Trojan_BAT_Formbook_MBZW_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MBZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c 07 11 [0-12] 91 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}