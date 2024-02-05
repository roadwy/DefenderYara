
rule Trojan_BAT_SnakeKeylogger_G_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 08 06 28 36 00 00 06 26 00 08 18 d6 0c 08 07 fe 02 16 fe 01 } //02 00 
		$a_01_1 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09 } //00 00 
	condition:
		any of ($a_*)
 
}