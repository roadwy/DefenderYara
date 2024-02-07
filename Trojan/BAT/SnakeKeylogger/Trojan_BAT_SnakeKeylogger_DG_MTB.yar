
rule Trojan_BAT_SnakeKeylogger_DG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 0a 00 00 14 00 "
		
	strings :
		$a_03_0 = {49 4d 47 5f 90 01 0b 2e 65 78 65 90 00 } //14 00 
		$a_03_1 = {49 4d 47 5f 90 01 0b 2e 43 6f 6e 6e 65 63 74 69 6f 6e 73 2e 53 74 61 74 65 2e 72 65 73 6f 75 72 63 65 73 90 00 } //14 00 
		$a_03_2 = {46 4c 5f 30 30 90 01 09 2e 65 78 65 90 00 } //14 00 
		$a_03_3 = {46 4c 5f 30 30 90 01 09 2e 44 69 63 74 69 6f 6e 61 72 69 65 73 90 00 } //14 00 
		$a_03_4 = {43 6f 6e 73 6f 6c 65 41 70 70 90 02 03 2e 65 78 65 90 00 } //14 00 
		$a_03_5 = {43 6f 6e 73 6f 6c 65 41 70 70 90 02 03 2e 44 65 66 69 6e 69 74 69 6f 6e 73 2e 4d 6f 63 6b 2e 72 65 73 6f 75 72 63 65 73 90 00 } //01 00 
		$a_81_6 = {54 65 6c 65 67 72 61 6d 20 44 65 73 6b 74 6f 70 } //01 00  Telegram Desktop
		$a_81_7 = {54 65 6c 65 67 72 61 6d 20 46 5a 2d 4c 4c 43 } //01 00  Telegram FZ-LLC
		$a_81_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_9 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}