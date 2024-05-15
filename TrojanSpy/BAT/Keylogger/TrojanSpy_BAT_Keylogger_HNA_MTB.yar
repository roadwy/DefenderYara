
rule TrojanSpy_BAT_Keylogger_HNA_MTB{
	meta:
		description = "TrojanSpy:BAT/Keylogger.HNA!MTB,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 52 4f 43 45 53 53 5f 53 55 53 50 45 4e 44 5f 52 45 53 55 4d 45 } //01 00  PROCESS_SUSPEND_RESUME
		$a_01_1 = {47 65 74 43 6f 6e 73 6f 6c 65 57 69 6e 64 6f 77 } //01 00  GetConsoleWindow
		$a_01_2 = {47 65 74 41 63 74 69 76 65 57 69 6e 64 6f 77 54 69 74 6c 65 } //01 00  GetActiveWindowTitle
		$a_01_3 = {47 65 74 4b 65 79 53 74 61 74 65 } //01 00  GetKeyState
		$a_01_4 = {41 70 70 65 6e 64 41 6c 6c 54 65 78 74 } //01 00  AppendAllText
		$a_01_5 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //01 00  CallNextHookEx
		$a_01_6 = {57 48 5f 4b 45 59 42 4f 41 52 44 } //01 00  WH_KEYBOARD
		$a_01_7 = {50 52 4f 43 45 53 53 5f 43 52 45 41 54 45 5f 54 48 52 45 41 44 } //01 00  PROCESS_CREATE_THREAD
		$a_01_8 = {57 48 5f 4b 45 59 42 4f 41 52 44 5f 4c 4c } //01 00  WH_KEYBOARD_LL
		$a_01_9 = {57 4d 5f 4b 45 59 44 4f 57 4e } //01 00  WM_KEYDOWN
		$a_01_10 = {50 52 4f 43 45 53 53 5f 41 4c 4c 5f 41 43 43 45 53 53 } //01 00  PROCESS_ALL_ACCESS
		$a_01_11 = {47 65 74 46 6f 72 65 67 72 6f 75 6e 64 57 69 6e 64 6f 77 } //01 00  GetForegroundWindow
		$a_01_12 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //01 00  SetWindowsHookEx
		$a_01_13 = {47 65 74 57 69 6e 64 6f 77 54 65 78 74 } //01 00  GetWindowText
		$a_01_14 = {47 65 74 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //00 00  GetKeyboardLayout
	condition:
		any of ($a_*)
 
}