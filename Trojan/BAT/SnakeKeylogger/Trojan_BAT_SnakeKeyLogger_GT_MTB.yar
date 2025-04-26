
rule Trojan_BAT_SnakeKeyLogger_GT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 01 11 01 6f 07 00 00 0a 11 01 6f 08 00 00 0a 6f 09 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}