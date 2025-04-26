
rule Trojan_BAT_SnakeKeylogger_PLYH_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.PLYH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 0a fe 02 0d 09 2c 06 72 ?? 00 00 70 0b 19 8d ?? 00 00 01 25 16 08 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 08 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 08 20 ?? 00 00 00 5f d2 9c 13 04 2b 00 11 04 2a } //6
		$a_03_1 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0d 2b 00 09 2a } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}