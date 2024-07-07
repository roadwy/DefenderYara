
rule Trojan_BAT_SnakeKeyLogger_RDX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 02 11 00 11 08 6f 07 00 00 0a 13 0c 20 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}