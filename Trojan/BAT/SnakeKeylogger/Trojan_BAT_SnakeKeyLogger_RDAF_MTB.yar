
rule Trojan_BAT_SnakeKeyLogger_RDAF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {09 02 7b 0e 00 00 04 6f 23 00 00 0a 02 7b 0e 00 00 04 6f 24 00 00 0a 13 04 } //00 00 
	condition:
		any of ($a_*)
 
}