
rule Trojan_BAT_SnakeKeylogger_EB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {14 0b 14 0c 28 90 01 03 06 74 06 00 00 1b 0c 08 17 28 90 01 03 06 a2 08 18 72 90 01 03 70 a2 08 16 28 90 01 03 06 a2 02 7b 90 01 03 04 08 28 90 01 03 0a 26 08 0a 2b 00 06 2a 90 00 } //01 00 
		$a_81_1 = {42 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 42 } //01 00 
		$a_81_2 = {53 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 53 } //01 00 
		$a_81_3 = {44 69 61 6c 6f 67 73 4c 69 62 } //00 00 
	condition:
		any of ($a_*)
 
}