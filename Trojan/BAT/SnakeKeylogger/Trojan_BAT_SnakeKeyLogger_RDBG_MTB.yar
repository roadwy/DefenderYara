
rule Trojan_BAT_SnakeKeyLogger_RDBG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 11 07 61 13 08 11 06 17 58 08 5d 08 58 08 5d 13 09 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}