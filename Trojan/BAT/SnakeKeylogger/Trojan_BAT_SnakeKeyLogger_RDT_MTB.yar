
rule Trojan_BAT_SnakeKeyLogger_RDT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {28 50 01 00 0a 6f 51 01 00 0a 28 90 01 04 6f 52 01 00 0a 6f 53 01 00 0a 13 06 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}