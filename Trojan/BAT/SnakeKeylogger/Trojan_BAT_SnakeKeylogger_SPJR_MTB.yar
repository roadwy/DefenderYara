
rule Trojan_BAT_SnakeKeylogger_SPJR_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {02 7b 12 00 00 04 07 11 04 08 59 09 11 06 02 7b 12 00 00 04 03 7b 25 00 00 04 11 04 09 11 06 03 6f 90 01 03 06 03 6f 90 01 03 06 00 00 11 06 17 58 13 06 11 06 1a fe 04 13 07 11 07 2d c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}