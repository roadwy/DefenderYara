
rule Trojan_BAT_SnakeKeyLogger_RDBQ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 5f 01 00 0a 6f 60 01 00 0a 0b 73 61 01 00 0a 0c 16 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}