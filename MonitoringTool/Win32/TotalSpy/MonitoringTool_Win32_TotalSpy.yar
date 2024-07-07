
rule MonitoringTool_Win32_TotalSpy{
	meta:
		description = "MonitoringTool:Win32/TotalSpy,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 76 00 69 00 73 00 69 00 62 00 69 00 6c 00 69 00 74 00 79 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 } //1 Invisibility Settings
		$a_01_1 = {46 72 65 65 20 4b 65 79 5f 6c 6f 67 67 65 72 } //1 Free Key_logger
		$a_01_2 = {5c 00 46 00 4b 00 4d 00 52 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 5c 00 63 00 6e 00 66 00 2e 00 64 00 61 00 74 00 } //1 \FKMR Manager\cnf.dat
		$a_01_3 = {4e 6f 20 73 63 72 65 65 6e 73 68 6f 74 73 20 66 6f 72 20 70 69 63 6b 65 64 20 64 61 74 65 2e } //1 No screenshots for picked date.
		$a_01_4 = {56 69 73 69 74 65 64 20 77 65 62 73 69 74 65 73 } //1 Visited websites
		$a_01_5 = {4b 65 79 73 74 72 6f 6b 65 20 6c 6f 67 67 69 6e 67 } //1 Keystroke logging
		$a_01_6 = {49 6e 76 69 73 69 62 6c 65 20 6d 6f 6e 69 74 6f 72 69 6e 67 20 69 73 20 73 74 61 72 74 69 6e 67 2e } //1 Invisible monitoring is starting.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}
rule MonitoringTool_Win32_TotalSpy_2{
	meta:
		description = "MonitoringTool:Win32/TotalSpy,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {75 6e 69 6e 73 74 61 6c 6c 20 54 6f 74 61 6c 20 53 70 79 } //1 uninstall Total Spy
		$a_01_2 = {43 6c 65 61 72 20 61 6c 6c 20 73 70 79 20 72 65 73 75 6c 74 20 66 69 6c 65 73 20 66 72 6f 6d 20 68 61 72 64 20 64 72 69 76 65 } //1 Clear all spy result files from hard drive
		$a_01_3 = {5c 73 70 79 5f 73 63 72 65 65 6e 73 68 6f 74 73 } //1 \spy_screenshots
		$a_01_4 = {53 65 74 43 6c 69 70 62 6f 61 72 64 56 69 65 77 65 72 } //1 SetClipboardViewer
		$a_01_5 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_01_6 = {43 6c 6f 73 65 43 6c 69 70 62 6f 61 72 64 } //1 CloseClipboard
		$a_01_7 = {45 6d 70 74 79 43 6c 69 70 62 6f 61 72 64 } //1 EmptyClipboard
		$a_01_8 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //1 GetKeyboardState
		$a_01_9 = {47 65 74 4b 65 79 4e 61 6d 65 54 65 78 74 41 } //1 GetKeyNameTextA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}
rule MonitoringTool_Win32_TotalSpy_3{
	meta:
		description = "MonitoringTool:Win32/TotalSpy,SIGNATURE_TYPE_PEHSTR,03 00 03 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 20 70 72 6f 67 72 61 6d 20 69 6e 20 48 69 64 64 65 6e 20 6d 6f 64 65 20 28 68 69 64 65 20 74 72 61 79 20 69 63 6f 6e 29 } //1 Start program in Hidden mode (hide tray icon)
		$a_01_1 = {48 69 64 64 65 6e 20 6d 6f 64 65 20 68 6f 74 6b 65 79 } //1 Hidden mode hotkey
		$a_01_2 = {41 70 70 6c 79 20 26 26 20 53 70 79 } //1 Apply && Spy
		$a_01_3 = {49 6e 76 69 73 69 62 69 6c 69 74 79 20 53 65 74 74 69 6e 67 73 } //1 Invisibility Settings
		$a_01_4 = {54 68 69 73 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 75 73 65 73 20 61 20 48 41 43 4b 45 44 20 76 65 72 73 69 6f 6e 20 6f 66 20 74 68 65 20 41 42 46 20 73 6f 66 74 77 61 72 65 2c 20 49 6e 63 2e 20 70 72 6f 64 75 63 74 2e } //1 This application uses a HACKED version of the ABF software, Inc. product.
		$a_01_5 = {67 61 61 76 74 20 70 72 6f 63 72 61 6d 20 69 6e 20 6f 69 64 63 65 6e 20 6d 6f 64 65 20 63 68 69 64 65 20 72 72 61 65 20 69 77 79 6e 29 } //2 gaavt procram in oidcen mode chide rrae iwyn)
		$a_01_6 = {48 69 64 64 65 77 20 63 72 74 65 20 68 68 74 74 65 79 } //1 Hiddew crte hhttey
		$a_01_7 = {41 70 70 69 79 76 7a 26 65 53 6c 79 } //1 Appiyvz&eSly
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=3
 
}