
rule Trojan_BAT_Formbook_KAO_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 5d 08 58 08 5d 13 [0-0f] 61 [0-05] 59 20 00 02 00 00 58 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}