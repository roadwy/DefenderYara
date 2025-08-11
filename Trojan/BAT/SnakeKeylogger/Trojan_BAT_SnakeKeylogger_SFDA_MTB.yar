
rule Trojan_BAT_SnakeKeylogger_SFDA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SFDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 1e 0f 00 28 ?? 00 00 0a 0c 2b 18 0f 00 28 ?? 00 00 0a 0c 2b 0e 0f 00 28 ?? 00 00 0a 0c 2b 04 16 0c 2b 00 08 2a } //2
		$a_03_1 = {02 11 05 11 07 6f ?? 00 00 0a 13 08 09 17 58 0d 05 13 0a 11 0a 39 ?? 00 00 00 00 11 04 13 0b 11 0b } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}