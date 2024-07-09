
rule Trojan_BAT_SnakeLogger_SPUT_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.SPUT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 0a 09 11 0a 91 11 05 61 11 04 11 07 91 61 28 ?? ?? ?? 0a 9c 11 07 1f 15 fe 01 13 0b 11 0b 2c 05 16 13 07 2b 06 11 07 17 58 13 07 00 11 0a 17 58 13 0a 11 0a 09 8e 69 17 59 fe 02 16 fe 01 13 0c 11 0c 2d b8 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}