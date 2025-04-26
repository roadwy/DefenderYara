
rule Trojan_BAT_SnakeKeylogger_SPQS_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 6f 1b 00 00 0a 07 9a 6f 1c 00 00 0a 14 14 6f 1d 00 00 0a 2c 02 de } //3
		$a_01_1 = {00 28 12 00 00 06 28 01 00 00 2b 28 02 00 00 2b 0a de 03 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}