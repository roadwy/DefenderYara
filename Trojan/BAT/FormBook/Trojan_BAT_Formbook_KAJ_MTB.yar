
rule Trojan_BAT_Formbook_KAJ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 25 17 6f 90 01 01 00 00 0a 25 18 6f 90 01 01 00 00 0a 25 02 6f 90 01 01 00 00 0a 25 03 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 04 16 04 8e 69 6f 90 01 01 00 00 0a 10 02 04 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}