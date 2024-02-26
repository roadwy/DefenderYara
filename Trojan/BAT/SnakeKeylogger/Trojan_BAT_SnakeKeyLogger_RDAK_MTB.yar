
rule Trojan_BAT_SnakeKeyLogger_RDAK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 04 03 8e 69 6f 90 01 04 0a 06 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}