
rule TrojanSpy_BAT_Keylogger_BC{
	meta:
		description = "TrojanSpy:BAT/Keylogger.BC,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 6d 65 6c 74 } //01 00  domelt
		$a_01_1 = {44 6f 77 6e 61 65 78 65 63 } //01 00  Downaexec
		$a_01_2 = {47 65 74 43 6f 6f 6c 6e 6f 76 6f } //01 00  GetCoolnovo
		$a_01_3 = {53 65 6e 64 50 61 73 73 77 6f 72 64 73 } //01 00  SendPasswords
		$a_01_4 = {44 69 73 61 62 6c 65 43 6f 6e 74 72 6f 6c 50 61 6e 65 6c } //01 00  DisableControlPanel
		$a_01_5 = {44 69 73 61 62 6c 65 4c 55 41 } //01 00  DisableLUA
		$a_01_6 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 47 52 } //01 00  DisableTaskMGR
		$a_01_7 = {47 00 61 00 6c 00 61 00 78 00 79 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 } //01 00  Galaxy Logger
		$a_01_8 = {5f 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 5f 00 } //01 00  _Passwords_
		$a_01_9 = {53 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 } //01 00  Screenshot
		$a_01_10 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_11 = {5d 04 00 00 e5 } //1e 03 
	condition:
		any of ($a_*)
 
}