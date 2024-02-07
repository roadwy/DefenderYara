
rule Trojan_BAT_SnakeKeylogger_EI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 05 00 00 14 00 "
		
	strings :
		$a_03_0 = {1b 0a 06 17 28 90 01 03 06 a2 06 18 72 90 01 03 70 a2 06 16 28 90 01 03 06 a2 02 7b 90 01 03 04 06 28 90 01 03 0a 26 06 2a 90 00 } //01 00 
		$a_81_1 = {58 5f 58 5f 58 5f 58 5f 41 5f 41 5f 41 5f 41 5f 53 5f 53 5f 53 5f 53 } //01 00  X_X_X_X_A_A_A_A_S_S_S_S
		$a_81_2 = {57 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 57 } //01 00  W__________W
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}