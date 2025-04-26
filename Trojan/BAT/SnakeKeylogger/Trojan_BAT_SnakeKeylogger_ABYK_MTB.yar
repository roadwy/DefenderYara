
rule Trojan_BAT_SnakeKeylogger_ABYK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 27 00 00 0a 0a 02 28 ?? 00 00 2b 6f ?? 00 00 0a 0b 38 ?? 00 00 00 07 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 2d ea dd ?? 00 00 00 07 39 ?? 00 00 00 07 6f ?? 00 00 0a dc 06 6f ?? 00 00 0a 2a } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}