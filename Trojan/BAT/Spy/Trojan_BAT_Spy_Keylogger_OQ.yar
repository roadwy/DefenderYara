
rule Trojan_BAT_Spy_Keylogger_OQ{
	meta:
		description = "Trojan:BAT/Spy.Keylogger.OQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 13 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {02 1f 43 fe 01 5f 2c 19 7e 90 01 03 04 72 90 01 03 70 28 90 01 03 0a 80 90 01 03 04 38 fc 35 00 00 28 90 01 03 06 6f 90 01 03 0a 6f 90 01 03 0a 02 1f 56 fe 01 5f 2c 19 7e 90 01 03 04 72 90 01 03 70 90 00 } //05 00 
		$a_80_1 = {47 72 69 65 76 65 20 4c 6f 67 67 65 72 20 50 75 62 6c 69 63 20 56 32 20 2d 20 4c 6f 67 73 3a } //Grieve Logger Public V2 - Logs:  05 00 
		$a_80_2 = {2b 3d 3d 3d 3d 4c 6f 67 73 3d 3d 3d 3d 2b } //+====Logs====+  04 00 
		$a_80_3 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //DisableTaskMgr  04 00 
		$a_02_4 = {5c 54 6d 70 90 01 04 2e 65 78 65 90 00 } //03 00 
		$a_80_5 = {67 65 74 5f 4b 65 79 62 6f 61 72 64 } //get_Keyboard  03 00 
		$a_80_6 = {67 65 74 5f 43 61 70 73 4c 6f 63 6b } //get_CapsLock  00 00 
	condition:
		any of ($a_*)
 
}