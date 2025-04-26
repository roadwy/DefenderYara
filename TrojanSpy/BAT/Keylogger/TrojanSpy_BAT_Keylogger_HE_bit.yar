
rule TrojanSpy_BAT_Keylogger_HE_bit{
	meta:
		description = "TrojanSpy:BAT/Keylogger.HE!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 6b 00 6c 00 6f 00 67 00 } //1 .klog
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {67 6c 6f 62 61 6c 4b 65 79 62 6f 61 72 64 48 6f 6f 6b } //1 globalKeyboardHook
		$a_01_3 = {5c 4b 65 79 4c 6f 67 67 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 4b 65 79 4c 6f 67 67 65 72 2e 70 64 62 } //1 \KeyLogger\obj\Debug\KeyLogger.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}