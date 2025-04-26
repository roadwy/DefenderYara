
rule Trojan_BAT_SnakeKeyLogger_MVT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.MVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {05 05 05 05 05 0e 06 28 08 00 00 06 0a 2b 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}