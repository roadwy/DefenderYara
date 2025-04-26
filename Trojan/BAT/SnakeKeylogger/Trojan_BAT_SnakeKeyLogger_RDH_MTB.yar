
rule Trojan_BAT_SnakeKeyLogger_RDH_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 09 18 6f 0f 01 00 0a 1f 10 28 10 01 00 0a 28 11 01 00 0a 16 91 13 05 08 11 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}