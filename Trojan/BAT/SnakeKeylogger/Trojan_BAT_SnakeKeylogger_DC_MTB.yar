
rule Trojan_BAT_SnakeKeylogger_DC_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 61 6d 65 42 6f 78 2e 4c 6f 67 6f 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_1 = {47 61 6d 65 42 6f 78 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00 
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_4 = {6f 70 65 6e 4b 65 79 62 6f 61 72 64 } //01 00 
		$a_81_5 = {52 65 70 6c 61 63 65 } //01 00 
		$a_81_6 = {67 65 74 5f 4b 65 79 } //01 00 
		$a_81_7 = {47 65 74 54 79 70 65 } //00 00 
	condition:
		any of ($a_*)
 
}