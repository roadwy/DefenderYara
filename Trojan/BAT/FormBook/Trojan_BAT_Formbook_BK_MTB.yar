
rule Trojan_BAT_Formbook_BK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 1f 10 62 0f 00 28 ?? 00 00 0a 1e 62 60 0f 00 28 ?? 00 00 0a 60 0a 03 19 8d ?? 00 00 01 25 16 06 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 06 1e 63 20 ff 00 00 00 5f d2 9c 25 18 06 20 ff 00 00 00 5f d2 9c 6f } //4
		$a_03_1 = {02 06 07 28 ?? 00 00 06 0c 08 03 04 28 ?? 00 00 06 00 00 07 17 58 0b 07 02 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}