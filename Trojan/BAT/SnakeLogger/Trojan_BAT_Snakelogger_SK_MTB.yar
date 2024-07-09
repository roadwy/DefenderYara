
rule Trojan_BAT_Snakelogger_SK_MTB{
	meta:
		description = "Trojan:BAT/Snakelogger.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 07 28 63 00 00 0a 16 fe 01 13 09 11 09 2c 0e 00 11 06 11 07 28 ?? ?? ?? 0a 00 00 2b 06 00 08 17 58 0c 00 00 2b 10 00 02 7b 14 00 00 04 11 06 6f ?? ?? ?? 0a 00 00 00 11 05 17 58 13 05 11 05 03 fe 04 13 0a 11 0a 3a 56 ff ff ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}