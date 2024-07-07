
rule TrojanSpy_BAT_Keylogger_Z{
	meta:
		description = "TrojanSpy:BAT/Keylogger.Z,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 00 26 00 44 00 67 00 6f 00 6c 00 6c 00 64 00 2e 00 63 00 6f 00 6d 00 } //1 %&Dgolld.com
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {64 00 65 00 66 00 6f 00 72 00 6d 00 61 00 63 00 69 00 6f 00 6e 00 } //1 deformacion
		$a_01_3 = {4b 42 44 4c 4c 48 6f 6f 6b 50 72 6f 63 } //1 KBDLLHookProc
		$a_01_4 = {49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 63 00 69 00 6f 00 6e 00 20 00 41 00 6e 00 6f 00 6e 00 79 00 6d 00 6f 00 75 00 73 00 42 00 61 00 72 00 74 00 } //1 Informacion AnonymousBart
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}