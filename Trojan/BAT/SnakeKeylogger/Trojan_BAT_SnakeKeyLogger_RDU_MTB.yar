
rule Trojan_BAT_SnakeKeyLogger_RDU_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 87 00 00 0a 6f 89 00 00 0a 06 06 6f 8a 00 00 0a 06 6f 8b 00 00 0a 6f 8c 00 00 0a 13 05 } //00 00 
	condition:
		any of ($a_*)
 
}