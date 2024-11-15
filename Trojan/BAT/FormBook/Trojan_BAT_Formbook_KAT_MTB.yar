
rule Trojan_BAT_Formbook_KAT_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 5a 58 20 00 ?? 00 00 5e 13 05 04 08 03 08 91 05 09 95 61 d2 9c 04 08 91 11 05 58 1f 33 61 20 ?? 00 00 00 5f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}