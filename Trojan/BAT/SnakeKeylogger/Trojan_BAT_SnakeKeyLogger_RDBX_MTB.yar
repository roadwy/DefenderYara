
rule Trojan_BAT_SnakeKeyLogger_RDBX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 0f 01 28 68 00 00 0a 6f 69 00 00 0a 00 02 0f 01 28 6a 00 00 0a 6f 69 00 00 0a 00 02 0f 01 28 6b 00 00 0a 6f 69 00 00 0a 00 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}