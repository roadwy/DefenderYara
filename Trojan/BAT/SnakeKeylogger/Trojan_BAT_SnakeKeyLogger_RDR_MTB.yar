
rule Trojan_BAT_SnakeKeyLogger_RDR_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 18 00 00 0a 6f 19 00 00 0a 28 26 00 00 06 6f 1a 00 00 0a 6f 1b 00 00 0a 13 01 } //00 00 
	condition:
		any of ($a_*)
 
}