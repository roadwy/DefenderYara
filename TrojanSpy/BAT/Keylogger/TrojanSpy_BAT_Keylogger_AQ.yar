
rule TrojanSpy_BAT_Keylogger_AQ{
	meta:
		description = "TrojanSpy:BAT/Keylogger.AQ,SIGNATURE_TYPE_PEHSTR_EXT,3d 00 3d 00 08 00 00 "
		
	strings :
		$a_01_0 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 3a 00 } //10 Keylogger:
		$a_01_1 = {53 65 6e 64 41 6c 6c } //10 SendAll
		$a_01_2 = {62 74 6e 45 6d 61 69 6c 4e 6f 77 5f 43 6c 69 63 6b } //10 btnEmailNow_Click
		$a_01_3 = {55 73 65 72 41 63 74 69 76 69 74 79 48 6f 6f 6b } //1 UserActivityHook
		$a_01_4 = {47 65 74 43 68 72 6f 6d 65 55 72 6c } //10 GetChromeUrl
		$a_01_5 = {46 69 6c 65 4c 6f 67 48 54 4d 4c } //10 FileLogHTML
		$a_01_6 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_7 = {48 6f 6f 6b 4d 61 6e 61 67 65 72 } //1 HookManager
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1) >=61
 
}