
rule Trojan_BAT_SnakeKeylogger_SPUT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPUT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 74 04 00 70 72 78 04 00 70 6f 90 01 03 0a 0d 07 28 90 01 03 0a 13 04 20 90 01 03 00 13 05 17 8d 90 01 03 01 25 16 7e 1f 00 00 04 a2 13 06 72 7a 04 00 70 72 47 06 00 70 72 78 04 00 70 28 90 01 03 0a 28 90 01 03 0a 13 07 11 07 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}