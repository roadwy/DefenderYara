
rule Trojan_BAT_SnakeKeylogger_ABQS_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 10 2b 15 2b 16 2b 1b 2b 1c 2b 21 2b 26 2b 2b de 2f 28 ?? ?? ?? 06 2b e9 0a 2b e8 28 ?? ?? ?? 0a 2b e3 06 2b e2 6f ?? ?? ?? 0a 2b dd 28 ?? ?? ?? 0a 2b d8 28 ?? ?? ?? 06 2b d3 0b 2b d2 26 de b9 } //3
		$a_01_1 = {07 91 9c 18 2c ed 19 2c 0f 02 07 08 9c 1c 2c e1 06 17 58 0a 07 17 59 0b 06 07 32 d7 02 2a } //3
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=7
 
}