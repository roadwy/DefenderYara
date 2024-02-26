
rule Trojan_BAT_SnakeKeyLogger_AC_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 05 00 00 06 28 05 00 00 06 28 05 00 00 06 28 05 00 00 06 28 05 00 00 06 72 49 00 00 70 16 28 0b 00 00 06 80 05 00 00 04 2a } //00 00 
	condition:
		any of ($a_*)
 
}