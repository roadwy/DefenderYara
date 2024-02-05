
rule Trojan_BAT_GrowtopiaKeylogger_A_MTB{
	meta:
		description = "Trojan:BAT/GrowtopiaKeylogger.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b 02 26 16 7e 05 00 00 04 73 09 00 00 0a 0a 06 20 90 01 02 00 00 28 3d 00 00 06 02 6a 20 90 01 02 00 00 28 3e 00 00 06 06 20 90 01 02 00 00 28 3f 00 00 06 28 0c 00 00 06 2a 90 00 } //02 00 
		$a_03_1 = {2b 02 26 16 02 20 90 01 02 00 00 28 40 00 00 06 0a 20 90 01 02 00 00 28 36 00 00 06 06 20 90 01 02 00 00 28 41 00 00 06 0b 07 2a 90 00 } //02 00 
		$a_03_2 = {09 11 04 11 05 11 06 73 90 01 01 00 00 0a 13 0a 20 90 01 02 00 00 17 58 28 0d 00 00 06 20 90 01 02 00 00 73 90 01 01 00 00 0a 13 0b 11 0b 17 20 90 01 02 00 00 28 2b 00 00 06 11 0b 11 07 11 08 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}