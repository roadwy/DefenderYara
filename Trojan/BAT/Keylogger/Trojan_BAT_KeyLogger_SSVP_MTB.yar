
rule Trojan_BAT_KeyLogger_SSVP_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.SSVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {7e 04 00 00 04 06 9a 6f 90 01 03 06 02 fe 01 0b 07 2c 05 00 17 0c 2b 15 00 06 17 58 0a 06 7e 05 00 00 04 fe 04 0d 09 2d d6 90 00 } //01 00 
		$a_01_1 = {6d 00 75 00 51 00 76 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}