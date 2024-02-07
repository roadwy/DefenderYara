
rule MonitoringTool_Win32_Rysio{
	meta:
		description = "MonitoringTool:Win32/Rysio,SIGNATURE_TYPE_PEHSTR,20 00 20 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {52 79 73 69 6f 4c 6f 67 67 65 72 20 } //0a 00  RysioLogger 
		$a_01_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //05 00  DisableTaskMgr
		$a_01_2 = {5c 70 6c 69 6b 2e 65 78 65 00 } //05 00 
		$a_01_3 = {00 41 6e 74 79 56 69 72 75 73 00 } //02 00 
		$a_01_4 = {68 61 73 6c 6f 00 } //02 00  慨汳o
		$a_01_5 = {6b 6c 69 6a 65 6e 74 } //01 00  klijent
		$a_01_6 = {6b 65 79 6c 6f 67 67 65 72 } //01 00  keylogger
		$a_01_7 = {4b 65 79 53 70 79 } //01 00  KeySpy
		$a_01_8 = {6f 6e 6d 6f 62 69 6c 65 6c 6f 67 } //01 00  onmobilelog
		$a_01_9 = {73 68 6f 77 63 6c 6f 63 6b 74 } //01 00  showclockt
		$a_01_10 = {6f 6e 62 72 6f 77 73 65 72 68 } //01 00  onbrowserh
		$a_01_11 = {53 63 72 65 65 6e 53 68 6f 74 } //00 00  ScreenShot
	condition:
		any of ($a_*)
 
}