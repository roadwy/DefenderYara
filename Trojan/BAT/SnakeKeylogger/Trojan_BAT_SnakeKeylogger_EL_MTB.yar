
rule Trojan_BAT_SnakeKeylogger_EL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {54 61 6e 6b 39 30 } //01 00  Tank90
		$a_81_1 = {74 61 6e 6b 5f 67 61 6d 65 5f 6f 76 65 72 2e 70 6e 67 } //01 00  tank_game_over.png
		$a_81_2 = {00 4f 4f 4f 4f 4f 00 } //01 00 
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_6 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_81_7 = {67 65 74 5f 59 } //01 00  get_Y
		$a_81_8 = {67 65 74 5f 58 } //00 00  get_X
	condition:
		any of ($a_*)
 
}