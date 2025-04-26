
rule MonitoringTool_Win32_PersonalInspector{
	meta:
		description = "MonitoringTool:Win32/PersonalInspector,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 61 6c 6c 4b 65 79 62 6f 61 72 64 48 6f 6f 6b } //1 InstallKeyboardHook
		$a_01_1 = {5b 50 52 49 4e 54 53 43 52 45 45 4e 5d } //2 [PRINTSCREEN]
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4b 4d 69 4e 54 32 31 5c 50 65 72 73 6f 6e 61 6c 49 6e 73 70 65 63 74 6f 72 } //3 SOFTWARE\KMiNT21\PersonalInspector
		$a_01_3 = {5c 69 6e 73 70 65 63 74 6f 72 2e 72 65 70 } //2 \inspector.rep
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=6
 
}
rule MonitoringTool_Win32_PersonalInspector_2{
	meta:
		description = "MonitoringTool:Win32/PersonalInspector,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {50 65 72 73 6f 6e 61 6c 20 49 6e 73 70 65 63 74 6f 72 } //1 Personal Inspector
		$a_00_1 = {4b 4d 69 4e 54 32 31 20 53 6f 66 74 77 61 72 65 } //1 KMiNT21 Software
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4b 4d 69 4e 54 32 31 5c 50 65 72 73 6f 6e 61 6c 49 6e 73 70 65 63 74 6f 72 } //1 Software\KMiNT21\PersonalInspector
		$a_00_3 = {73 76 63 6d 6f 6e 2e 64 6c 6c } //1 svcmon.dll
		$a_00_4 = {73 76 63 6d 6f 6e 2e 65 78 65 } //1 svcmon.exe
		$a_00_5 = {72 76 69 65 77 2e 65 78 65 } //1 rview.exe
		$a_01_6 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 SetClipboardData
		$a_00_7 = {54 72 61 63 6b 50 6f 70 75 70 4d 65 6e 75 } //1 TrackPopupMenu
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}