
rule TrojanSpy_BAT_VB_A{
	meta:
		description = "TrojanSpy:BAT/VB.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //01 00  Advanced Keylogger
		$a_00_1 = {3c 00 53 00 63 00 72 00 6f 00 6c 00 6c 00 4c 00 6f 00 63 00 6b 00 20 00 4f 00 66 00 66 00 3e 00 } //01 00  <ScrollLock Off>
		$a_00_2 = {54 00 68 00 65 00 20 00 57 00 69 00 72 00 65 00 73 00 68 00 61 00 72 00 6b 00 20 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 41 00 6e 00 61 00 6c 00 79 00 7a 00 65 00 72 00 } //02 00  The Wireshark Network Analyzer
		$a_00_3 = {4c 00 6f 00 67 00 66 00 69 00 6c 00 65 00 73 00 20 00 66 00 72 00 6f 00 6d 00 20 00 45 00 61 00 73 00 79 00 4c 00 6f 00 67 00 67 00 65 00 72 00 } //01 00  Logfiles from EasyLogger
		$a_01_4 = {4b 65 79 62 6f 61 72 64 48 6f 6f 6b 44 65 6c 65 67 61 74 65 } //02 00  KeyboardHookDelegate
		$a_01_5 = {61 6e 74 69 53 61 6e 64 62 6f 78 69 65 } //02 00  antiSandboxie
		$a_01_6 = {5c 4b 72 65 79 6c 6f 67 67 65 72 20 53 6f 75 72 63 65 5c 67 6d 61 69 6c 20 4b 65 79 6c 6f 67 67 65 72 5c 4d 79 20 4b 65 79 6c 6f 67 67 65 72 5c } //00 00  \Kreylogger Source\gmail Keylogger\My Keylogger\
	condition:
		any of ($a_*)
 
}