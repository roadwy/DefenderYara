
rule Trojan_BAT_SnakeLogger_BG_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 2c 07 09 6f ?? 00 00 0a 00 dc 28 ?? 00 00 06 0b 28 ?? 00 00 06 07 16 07 8e 69 6f ?? 00 00 0a 0c 08 28 ?? 00 00 06 26 00 de 0b } //3
		$a_03_1 = {0d 00 09 28 ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 7e ?? 00 00 04 11 04 6f ?? 00 00 0a 00 00 de 0b } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}