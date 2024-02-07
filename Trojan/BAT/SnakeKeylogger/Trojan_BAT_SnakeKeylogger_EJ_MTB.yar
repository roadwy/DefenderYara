
rule Trojan_BAT_SnakeKeylogger_EJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_81_0 = {24 31 31 65 34 34 38 63 36 2d 30 31 65 36 2d 34 63 65 37 2d 61 63 64 36 2d 64 64 38 33 31 61 39 32 34 64 30 31 } //01 00  $11e448c6-01e6-4ce7-acd6-dd831a924d01
		$a_81_1 = {58 5f 58 5f 58 5f 58 5f 41 5f 41 5f 41 5f 41 5f 53 5f 53 5f 53 5f 53 } //01 00  X_X_X_X_A_A_A_A_S_S_S_S
		$a_81_2 = {57 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 57 } //01 00  W__________W
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}