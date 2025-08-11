
rule Trojan_BAT_MassLogger_ZQV_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.ZQV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {1b 5d 0b 07 1a 2e 0e 07 19 2e 0a 07 18 2e 06 07 17 fe 01 2b 01 17 13 05 11 05 2c 02 16 0b 28 ?? 00 00 0a 17 fe 02 0c 19 8d ?? 00 00 1b 25 16 06 fe 06 43 00 00 06 73 ?? 00 00 0a a2 25 17 06 fe 06 44 00 00 06 73 ?? 00 00 0a a2 25 18 06 fe 06 45 00 00 06 73 ?? 00 00 0a a2 0d 06 09 07 9a 7d ?? 00 00 04 06 06 fe 06 46 00 00 06 73 ?? 00 00 0a 7d 4b 00 00 04 08 13 06 11 06 2c 0b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}