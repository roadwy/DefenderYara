
rule Trojan_BAT_SnakeLogger_SPAU_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.SPAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 11 06 07 11 06 9a 1f 10 28 90 01 03 0a d2 9c 00 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 2d db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}