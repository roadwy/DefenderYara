
rule MonitoringTool_Win32_MiniKeyLog{
	meta:
		description = "MonitoringTool:Win32/MiniKeyLog,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 69 6d 70 6c 65 20 6b 65 79 6c 6f 67 67 65 72 20 3c } //10 Simple keylogger <
		$a_02_1 = {8b c3 0d 00 00 00 40 3b d8 75 6a 68 ?? ?? 40 00 6a 00 e8 ?? ff ff ff 89 45 fc 68 ?? ?? 40 00 e8 ?? ff ff ff } //10
		$a_00_2 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //1 GetKeyboardState
		$a_00_3 = {53 65 74 4b 65 79 48 6f 6f 6b } //1 SetKeyHook
		$a_00_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=22
 
}
rule MonitoringTool_Win32_MiniKeyLog_2{
	meta:
		description = "MonitoringTool:Win32/MiniKeyLog,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 00 69 00 6e 00 69 00 20 00 4b 00 65 00 79 00 20 00 4c 00 6f 00 67 00 20 00 2d 00 20 00 50 00 43 00 20 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 } //1 Mini Key Log - PC Monitoring Software
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 62 00 6c 00 75 00 65 00 2d 00 73 00 65 00 72 00 69 00 65 00 73 00 2e 00 64 00 65 00 } //1 http://www.blue-series.de
		$a_01_2 = {4d 00 69 00 6e 00 69 00 4b 00 65 00 79 00 4c 00 6f 00 67 00 } //1 MiniKeyLog
		$a_01_3 = {70 75 62 6c 69 63 4b 65 79 54 6f 6b 65 6e 3d 22 36 35 39 35 62 36 34 31 34 34 63 63 66 31 64 66 22 } //1 publicKeyToken="6595b64144ccf1df"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}