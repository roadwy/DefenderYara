
rule Trojan_BAT_SnakeKeyLogger_RDCJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 05 17 73 0a 00 00 0a 13 07 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}