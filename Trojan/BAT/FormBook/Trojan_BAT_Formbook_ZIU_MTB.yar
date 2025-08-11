
rule Trojan_BAT_Formbook_ZIU_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZIU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 15 5f 13 09 11 09 06 17 17 28 ?? 00 00 0a 5a 06 17 16 28 ?? 00 00 0a 26 16 58 06 17 18 28 ?? 00 00 0a 26 16 58 13 0a 02 11 08 11 0a 6f ?? 00 00 0a 13 0b 12 0b 28 ?? 00 00 0a 13 0c 12 0b 28 ?? 00 00 0a 13 0d 12 0b 28 ?? 00 00 0a 13 0e 04 03 6f ?? 00 00 0a 59 13 0f 11 0f 19 fe 04 16 fe 01 13 10 11 10 2c 54 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}