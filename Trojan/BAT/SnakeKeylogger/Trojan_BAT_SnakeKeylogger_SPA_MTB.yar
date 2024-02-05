
rule Trojan_BAT_SnakeKeylogger_SPA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 11 04 07 8e 69 5d 02 07 11 04 28 90 01 03 06 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d d9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}