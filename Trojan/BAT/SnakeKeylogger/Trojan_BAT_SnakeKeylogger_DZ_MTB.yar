
rule Trojan_BAT_SnakeKeylogger_DZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 42 } //01 00 
		$a_81_1 = {53 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 53 } //01 00 
		$a_81_2 = {44 69 61 6c 6f 67 73 4c 69 62 } //01 00 
		$a_81_3 = {4b 65 79 45 76 65 6e 74 41 72 67 73 } //01 00 
		$a_81_4 = {4b 65 79 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //01 00 
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_6 = {53 75 73 70 65 6e 64 4c 61 79 6f 75 74 } //01 00 
		$a_81_7 = {54 6f 42 79 74 65 } //01 00 
		$a_81_8 = {41 63 74 69 76 61 74 6f 72 } //01 00 
		$a_81_9 = {52 65 70 6c 61 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}