
rule Trojan_BAT_LokiBot_RPH_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d b8 06 17 58 0a 00 09 17 58 0d 09 20 00 ?? 01 00 fe 04 13 06 11 06 2d 9b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_LokiBot_RPH_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 04 9a 13 05 11 05 14 fe 01 13 06 11 06 2c 02 2b 48 11 05 2c 12 11 05 7e 75 00 00 0a 16 28 76 00 00 0a 16 fe 03 2b 01 16 13 07 11 07 2c 2a 08 18 8d 03 00 00 01 25 16 11 04 8c 42 00 00 01 a2 25 17 11 05 28 77 00 00 0a 04 da 8c 42 00 00 01 a2 14 28 78 00 00 0a 00 00 00 11 04 17 d6 13 04 11 04 09 31 9a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}