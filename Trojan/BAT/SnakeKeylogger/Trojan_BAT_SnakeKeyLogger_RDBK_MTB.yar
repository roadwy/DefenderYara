
rule Trojan_BAT_SnakeKeyLogger_RDBK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 28 03 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f 1f 00 00 0a 08 13 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}