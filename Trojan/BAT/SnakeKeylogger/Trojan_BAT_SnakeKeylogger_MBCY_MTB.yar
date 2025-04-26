
rule Trojan_BAT_SnakeKeylogger_MBCY_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MBCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 13 12 11 11 13 13 12 0f 28 ?? 00 00 0a 11 12 28 ?? 00 00 06 16 1e 6f ?? 00 00 0a 13 14 11 14 11 13 73 ?? 00 00 06 13 15 06 11 0f 11 15 6f ?? 00 00 0a 00 00 11 0e 17 58 13 0e 11 0e 11 09 fe 04 13 16 11 16 2d 84 } //1
		$a_01_1 = {39 31 64 63 64 61 66 61 33 37 34 63 } //1 91dcdafa374c
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}