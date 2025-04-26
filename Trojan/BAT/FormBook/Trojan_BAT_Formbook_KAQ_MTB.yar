
rule Trojan_BAT_Formbook_KAQ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {95 58 20 ff 00 00 00 5f [0-1e] 95 61 28 ?? 00 00 0a 9c [0-23] 09 8e 69 32 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}