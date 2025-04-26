
rule Trojan_BAT_SnakeKeyLogger_RDBS_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 6a 00 00 2b 8e 69 6f 54 04 00 0a 08 6f 55 04 00 0a 13 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}