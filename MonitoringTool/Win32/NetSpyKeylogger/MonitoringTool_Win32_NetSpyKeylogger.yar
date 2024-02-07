
rule MonitoringTool_Win32_NetSpyKeylogger{
	meta:
		description = "MonitoringTool:Win32/NetSpyKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd3 00 ffffffd3 00 0d 00 00 64 00 "
		
	strings :
		$a_01_0 = {53 70 79 43 6c 61 73 73 00 } //64 00 
		$a_01_1 = {52 65 6d 6f 74 65 53 70 79 00 } //01 00  敒潭整灓y
		$a_00_2 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00  ZwQuerySystemInformation
		$a_01_3 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  SetWindowsHookExA
		$a_00_4 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //01 00  UnhookWindowsHookEx
		$a_01_5 = {49 4d 41 47 45 48 4c 50 2e 64 6c 6c } //01 00  IMAGEHLP.dll
		$a_01_6 = {47 65 74 4c 61 73 74 54 69 63 6b 43 6f 75 6e 74 } //01 00  GetLastTickCount
		$a_01_7 = {4b 65 79 48 6f 6f 6b 50 72 6f 63 } //01 00  KeyHookProc
		$a_01_8 = {4c 6f 61 64 00 } //01 00 
		$a_01_9 = {4d 6f 75 73 65 48 6f 6f 6b 50 72 6f 63 } //01 00  MouseHookProc
		$a_01_10 = {52 65 6d 6f 76 65 48 6f 6f 6b 00 } //01 00 
		$a_01_11 = {53 65 74 48 6f 6f 6b 00 } //01 00  敓䡴潯k
		$a_01_12 = {53 65 74 4f 70 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}