
rule TrojanSpy_BAT_Keylogger_SV_MTB{
	meta:
		description = "TrojanSpy:BAT/Keylogger.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 2e 70 64 62 } //1 Windows Defender.pdb
		$a_01_1 = {53 69 6e 67 6c 65 46 69 6c 65 47 65 6e 65 72 61 74 6f 72 } //1 SingleFileGenerator
		$a_01_2 = {47 65 74 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //1 GetKeyboardLayout
		$a_01_3 = {4c 6f 77 4c 65 76 65 6c 4b 65 79 62 6f 61 72 64 50 72 6f 63 } //1 LowLevelKeyboardProc
		$a_01_4 = {57 4d 5f 4b 45 59 44 4f 57 4e } //1 WM_KEYDOWN
		$a_01_5 = {57 48 5f 4b 45 59 42 4f 41 52 44 5f 4c 4c } //1 WH_KEYBOARD_LL
		$a_01_6 = {74 65 73 74 77 65 66 77 65 66 5c 74 65 73 74 77 65 66 77 65 66 } //1 testwefwef\testwefwef
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}