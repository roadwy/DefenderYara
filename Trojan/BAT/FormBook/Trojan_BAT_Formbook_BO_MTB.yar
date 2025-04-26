
rule Trojan_BAT_Formbook_BO_MTB{
	meta:
		description = "Trojan:BAT/Formbook.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 6f ?? 00 00 0a 58 02 6f ?? 00 00 0a 5d 11 05 02 6f ?? 00 00 0a 58 02 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 13 07 04 03 6f ?? 00 00 0a 59 13 08 11 07 11 08 03 } //4
		$a_03_1 = {17 58 13 05 11 05 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}