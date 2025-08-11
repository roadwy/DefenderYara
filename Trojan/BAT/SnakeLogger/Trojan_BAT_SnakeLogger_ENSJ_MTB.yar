
rule Trojan_BAT_SnakeLogger_ENSJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.ENSJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {15 6e 61 15 6e 61 7d 87 00 00 04 06 73 69 00 00 0a 7d 86 00 00 04 06 7b 86 00 00 04 72 66 05 00 70 16 1f 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}