
rule Trojan_BAT_BPLogger_AKXA_MTB{
	meta:
		description = "Trojan:BAT/BPLogger.AKXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 02 02 11 02 91 03 11 02 11 01 5d 6f ?? 00 00 0a 61 d2 9c 20 } //4
		$a_01_1 = {11 02 17 58 13 02 20 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}