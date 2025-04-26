
rule Trojan_BAT_Formbook_AUJ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 11 05 9a 28 81 01 00 0a 20 98 00 00 00 da b4 13 06 09 11 06 6f 82 01 00 0a 00 11 05 17 d6 13 05 11 05 11 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}