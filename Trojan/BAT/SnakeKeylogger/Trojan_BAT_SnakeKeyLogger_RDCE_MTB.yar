
rule Trojan_BAT_SnakeKeyLogger_RDCE_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0c 72 b1 00 00 70 28 1b 00 00 06 72 e3 00 00 70 28 1b 00 00 06 28 1c 00 00 06 13 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}