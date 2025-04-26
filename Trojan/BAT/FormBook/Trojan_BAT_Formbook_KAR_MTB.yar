
rule Trojan_BAT_Formbook_KAR_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 08 59 0d 09 16 30 03 16 2b 01 17 13 04 08 19 58 04 fe 02 16 fe 01 13 05 11 05 2c 07 11 04 17 fe 01 2b 01 16 13 06 11 06 2c 0f 00 03 07 28 ?? 00 00 06 00 00 38 ?? 00 00 00 00 09 17 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}