
rule TrojanSpy_Win32_Keylogger_HC_bit{
	meta:
		description = "TrojanSpy:Win32/Keylogger.HC!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 00 6b 00 6f 00 6e 00 61 00 77 00 61 00 72 00 6b 00 61 00 00 00 } //01 00 
		$a_01_1 = {00 00 5b 00 41 00 4c 00 54 00 44 00 4f 00 57 00 4e 00 5d 00 00 00 } //01 00 
		$a_01_2 = {47 65 74 4b 65 79 53 74 61 74 65 } //01 00  GetKeyState
		$a_01_3 = {47 65 74 46 6f 72 65 67 72 6f 75 6e 64 57 69 6e 64 6f 77 } //01 00  GetForegroundWindow
		$a_01_4 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //00 00  GetAsyncKeyState
	condition:
		any of ($a_*)
 
}