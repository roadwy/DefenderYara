
rule MonitoringTool_Win32_FreeQuickKeylogger{
	meta:
		description = "MonitoringTool:Win32/FreeQuickKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 69 64 65 53 74 65 70 20 46 72 65 65 20 4c 69 63 65 6e 73 65 20 41 67 72 65 65 6d 65 6e 74 } //1 WideStep Free License Agreement
		$a_01_1 = {46 72 65 65 20 51 75 69 63 6b 20 4b 65 79 6c 6f 67 67 65 72 } //1 Free Quick Keylogger
		$a_01_2 = {71 75 69 63 6b 5f 65 6e 67 69 6e 65 2e 65 78 65 00 71 6b 5f 75 73 65 72 5f 67 75 69 64 65 2e 68 74 6d 00 51 75 69 63 6b 41 70 70 49 6e 69 74 2e 64 6c 6c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule MonitoringTool_Win32_FreeQuickKeylogger_2{
	meta:
		description = "MonitoringTool:Win32/FreeQuickKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0d 00 00 "
		
	strings :
		$a_01_0 = {46 72 65 65 20 51 75 69 63 6b 20 4b 65 79 6c 6f 67 67 65 72 20 4c 6f 67 2e 68 74 6d } //1 Free Quick Keylogger Log.htm
		$a_01_1 = {77 69 64 65 73 74 65 70 2e 63 6f 6d } //1 widestep.com
		$a_01_2 = {46 72 65 65 20 51 75 69 63 6b 20 4b 65 79 6c 6f 67 67 65 72 20 69 73 20 61 6c 72 65 61 64 79 20 72 75 6e 6e 69 6e 67 2e } //1 Free Quick Keylogger is already running.
		$a_01_3 = {54 68 61 6e 6b 20 79 6f 75 20 66 6f 72 20 63 68 6f 6f 73 69 6e 67 20 46 72 65 65 20 51 75 69 63 6b 20 4b 65 79 6c 6f 67 67 65 72 } //1 Thank you for choosing Free Quick Keylogger
		$a_01_4 = {48 57 5f 4b 45 59 42 4f 41 52 44 20 68 6f 6f 6b 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 73 75 63 63 65 73 73 66 75 6c 2e } //1 HW_KEYBOARD hook installation successful.
		$a_01_5 = {48 57 5f 47 45 54 4d 45 53 53 41 47 45 20 68 6f 6f 6b 20 75 6e 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 73 75 63 63 65 73 73 66 75 6c 2e } //1 HW_GETMESSAGE hook uninstallation successful.
		$a_01_6 = {71 75 69 63 6b 5f 65 6e 67 69 6e 65 2e 65 78 65 } //1 quick_engine.exe
		$a_01_7 = {71 75 69 63 6b 6c 6f 67 73 2e 62 69 6e } //1 quicklogs.bin
		$a_01_8 = {71 75 69 63 6b 2e 6a 72 6e } //1 quick.jrn
		$a_01_9 = {6f 6e 65 20 69 6e 73 74 61 6e 63 65 20 6f 66 20 74 68 65 20 46 72 65 65 20 51 75 69 63 6b 20 4b 65 79 6c 6f 67 67 65 72 20 63 61 6e 20 62 65 20 6c 61 75 6e 63 68 65 64 } //1 one instance of the Free Quick Keylogger can be launched
		$a_01_10 = {77 68 69 6c 65 20 73 77 69 74 63 68 69 6e 67 20 74 6f 20 69 6e 76 69 73 69 62 6c 65 20 6d 6f 64 65 2e } //1 while switching to invisible mode.
		$a_01_11 = {53 50 59 4b 45 59 48 4f 4f 4b } //1 SPYKEYHOOK
		$a_01_12 = {7b 73 65 74 75 70 20 6b 65 79 62 6f 61 72 64 20 68 6f 6f 6b 73 7d } //1 {setup keyboard hooks}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=4
 
}