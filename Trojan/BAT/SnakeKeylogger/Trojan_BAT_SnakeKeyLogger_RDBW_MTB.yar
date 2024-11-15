
rule Trojan_BAT_SnakeKeyLogger_RDBW_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 07 06 6f 30 00 00 0a 17 73 31 00 00 0a 0c 08 02 16 02 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}