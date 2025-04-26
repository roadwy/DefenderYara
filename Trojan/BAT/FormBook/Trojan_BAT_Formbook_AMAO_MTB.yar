
rule Trojan_BAT_Formbook_AMAO_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 58 09 8e 69 5d 91 13 ?? 07 11 ?? 08 5d 08 58 08 5d 91 11 ?? 61 [0-05] 17 58 08 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}