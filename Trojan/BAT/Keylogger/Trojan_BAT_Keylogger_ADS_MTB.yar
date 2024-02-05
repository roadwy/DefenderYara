
rule Trojan_BAT_Keylogger_ADS_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.ADS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 03 00 "
		
	strings :
		$a_80_0 = {4c 6f 77 4c 65 76 65 6c 4b 65 79 62 6f 61 72 64 50 72 6f 63 } //LowLevelKeyboardProc  03 00 
		$a_80_1 = {47 65 74 4b 65 79 53 74 61 74 65 } //GetKeyState  03 00 
		$a_80_2 = {4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //KeyboardLayout  03 00 
		$a_80_3 = {5b 53 50 41 43 45 5d } //[SPACE]  03 00 
		$a_80_4 = {5b 45 4e 54 45 52 5d } //[ENTER]  03 00 
		$a_80_5 = {5b 45 53 43 5d } //[ESC]  03 00 
		$a_80_6 = {5b 43 54 52 4c 5d } //[CTRL]  03 00 
		$a_80_7 = {4b 65 79 6c 6f 67 67 65 72 } //Keylogger  03 00 
		$a_80_8 = {4d 61 70 56 69 72 74 75 61 6c 4b 65 79 } //MapVirtualKey  00 00 
	condition:
		any of ($a_*)
 
}