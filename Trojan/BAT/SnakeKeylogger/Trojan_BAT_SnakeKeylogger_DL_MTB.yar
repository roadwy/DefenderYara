
rule Trojan_BAT_SnakeKeylogger_DL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 07 00 00 14 00 "
		
	strings :
		$a_03_0 = {4e 65 77 20 4f 72 64 65 72 20 52 65 71 75 65 73 74 73 90 02 0f 2e 65 78 65 90 00 } //05 00 
		$a_81_1 = {54 65 6c 65 67 72 61 6d 20 44 65 73 6b 74 6f 70 } //05 00  Telegram Desktop
		$a_81_2 = {54 65 6c 65 67 72 61 6d 20 46 5a 2d 4c 4c 43 } //01 00  Telegram FZ-LLC
		$a_81_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_4 = {44 65 63 72 79 70 74 } //01 00  Decrypt
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}