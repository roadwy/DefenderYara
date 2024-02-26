
rule Trojan_BAT_SnakeKeyLogger_RDAR_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {5d 91 08 58 08 5d 59 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}