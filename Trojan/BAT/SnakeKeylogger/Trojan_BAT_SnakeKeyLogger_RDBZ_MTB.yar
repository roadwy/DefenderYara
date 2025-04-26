
rule Trojan_BAT_SnakeKeyLogger_RDBZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 07 09 11 04 6f 7b 00 00 0a 13 05 73 7c 00 00 0a 0a 06 11 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}