
rule Trojan_BAT_Formbook_ZKV_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 09 17 94 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 13 0a 11 0a 2d 95 08 08 61 0c 00 11 04 17 58 13 04 11 04 09 16 94 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 13 0b 11 0b } //6
		$a_03_1 = {07 02 11 04 11 05 6f ?? 00 00 06 13 06 04 03 6f ?? 00 00 0a 59 13 07 11 07 19 28 ?? 00 00 06 13 08 11 08 2c 0d 00 03 11 06 28 ?? 00 00 06 00 00 2b 18 11 07 16 fe 02 13 09 11 09 2c 0d } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}