
rule Trojan_BAT_SnakeKeyLogger_RDO_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 22 01 00 06 28 4f 00 00 0a 6f 50 00 00 0a 6f 51 00 00 0a 6f 52 00 00 0a 6f 53 00 00 0a 13 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}