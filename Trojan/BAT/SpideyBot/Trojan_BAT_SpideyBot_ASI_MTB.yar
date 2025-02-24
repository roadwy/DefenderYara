
rule Trojan_BAT_SpideyBot_ASI_MTB{
	meta:
		description = "Trojan:BAT/SpideyBot.ASI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 7e 1a 00 00 04 25 2d 17 26 7e 19 00 00 04 fe 06 46 00 00 06 73 67 00 00 0a 25 80 1a 00 00 04 28 ?? 00 00 2b 0c 08 14 fe 03 0d 09 2c 0b 00 08 } //3
		$a_03_1 = {0a 00 06 0b 16 0c 2b 6c 07 08 9a 0d 00 09 6f ?? 00 00 0a 03 28 ?? 00 00 0a 13 04 11 04 2c 50 00 09 6f ?? 00 00 0a 13 08 12 08 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}