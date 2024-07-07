
rule Trojan_BAT_Formbook_AMBF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 07 11 90 01 01 20 90 01 04 5d 91 11 90 01 01 58 11 90 01 01 5d 59 d2 9c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}