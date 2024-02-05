
rule Trojan_BAT_SnakeKeylogger_EG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 14 00 "
		
	strings :
		$a_03_0 = {14 0b 14 0c 28 90 01 03 06 74 90 01 03 1b 0c 08 17 28 90 01 03 06 a2 08 18 72 90 01 03 70 a2 08 16 28 90 01 03 06 a2 02 7b 90 01 03 04 08 28 90 01 03 0a 26 08 0a 2b 00 06 2a 90 00 } //01 00 
		$a_81_1 = {58 5f 58 5f 58 5f 58 5f 41 5f 41 5f 41 5f 41 5f 53 5f 53 5f 53 5f 53 } //01 00 
		$a_81_2 = {57 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 57 } //01 00 
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } //01 00 
		$a_81_5 = {47 65 74 54 79 70 65 } //00 00 
	condition:
		any of ($a_*)
 
}