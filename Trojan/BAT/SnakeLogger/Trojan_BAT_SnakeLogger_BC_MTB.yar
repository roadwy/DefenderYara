
rule Trojan_BAT_SnakeLogger_BC_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 0c 2b 2d 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 14 03 6f ?? 00 00 0a 19 58 04 fe 02 16 fe 01 13 04 11 04 2d } //2
		$a_03_1 = {03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 2b 1a 09 17 fe 01 13 08 11 08 2c 10 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 00 07 17 58 0b 00 07 02 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}