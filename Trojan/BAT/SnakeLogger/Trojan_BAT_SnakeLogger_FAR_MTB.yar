
rule Trojan_BAT_SnakeLogger_FAR_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.FAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 01 2a 00 72 90 01 01 00 00 70 28 90 01 01 00 00 06 13 00 38 00 00 00 00 28 90 01 01 00 00 0a 11 00 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 13 01 38 00 00 00 00 dd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}