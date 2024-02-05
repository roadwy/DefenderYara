
rule Trojan_BAT_SnakeLogger_FAX_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.FAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 29 00 07 09 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 13 06 08 17 8d 90 01 01 00 00 01 25 16 11 06 9c 6f 90 01 01 00 00 0a 00 09 18 58 0d 00 09 07 6f 90 01 01 00 00 0a fe 04 13 07 11 07 2d c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}