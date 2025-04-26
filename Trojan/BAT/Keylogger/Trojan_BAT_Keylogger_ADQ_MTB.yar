
rule Trojan_BAT_Keylogger_ADQ_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.ADQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 0b 00 00 "
		
	strings :
		$a_80_0 = {4c 6f 77 4c 65 76 65 6c 4b 65 79 62 6f 61 72 64 50 72 6f 63 } //LowLevelKeyboardProc  5
		$a_80_1 = {47 65 74 4b 65 79 53 74 61 74 65 } //GetKeyState  5
		$a_80_2 = {4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //KeyboardLayout  5
		$a_80_3 = {5b 53 50 41 43 45 5d } //[SPACE]  4
		$a_80_4 = {5b 45 4e 54 45 52 5d } //[ENTER]  4
		$a_80_5 = {5b 45 53 43 5d } //[ESC]  4
		$a_80_6 = {5b 43 54 52 4c 5d } //[CTRL]  4
		$a_80_7 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //GetKeyboardState  4
		$a_80_8 = {53 57 52 61 74 } //SWRat  3
		$a_80_9 = {57 49 4e 44 4f 57 53 5f 46 49 52 45 57 41 4c 4c 5f 53 45 52 56 49 43 45 } //WINDOWS_FIREWALL_SERVICE  3
		$a_80_10 = {48 61 63 6b 65 64 } //Hacked  3
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4+(#a_80_5  & 1)*4+(#a_80_6  & 1)*4+(#a_80_7  & 1)*4+(#a_80_8  & 1)*3+(#a_80_9  & 1)*3+(#a_80_10  & 1)*3) >=44
 
}