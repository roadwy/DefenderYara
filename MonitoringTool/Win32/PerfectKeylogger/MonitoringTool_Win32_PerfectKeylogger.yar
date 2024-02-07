
rule MonitoringTool_Win32_PerfectKeylogger{
	meta:
		description = "MonitoringTool:Win32/PerfectKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 69 5f 62 70 6b 5f 74 72 69 61 6c 2e 65 78 65 } //01 00  /i_bpk_trial.exe
		$a_01_1 = {63 6f 6e 6e 65 63 74 65 64 20 74 6f 20 49 6e 74 65 72 6e 65 74 } //01 00  connected to Internet
		$a_01_2 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 69 00 6e 00 67 00 20 00 50 00 65 00 72 00 66 00 65 00 63 00 74 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 } //00 00  Downloading Perfect Keylogger.
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_PerfectKeylogger_2{
	meta:
		description = "MonitoringTool:Win32/PerfectKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 09 00 00 03 00 "
		
	strings :
		$a_00_0 = {00 72 69 6e 73 74 2e 65 78 65 00 } //03 00 
		$a_00_1 = {00 62 70 6b 2e 64 61 74 00 } //02 00 
		$a_00_2 = {00 70 6b 2e 62 69 6e 00 } //02 00 
		$a_01_3 = {50 4b 4c 20 57 69 6e 64 6f 77 } //02 00  PKL Window
		$a_00_4 = {62 6c 61 7a 69 6e 67 74 6f 6f 6c 73 } //01 00  blazingtools
		$a_00_5 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //01 00  InternetGetConnectedState
		$a_00_6 = {00 68 6b 2e 64 6c 6c 00 } //01 00 
		$a_00_7 = {00 77 62 2e 64 6c 6c 00 } //01 00 
		$a_00_8 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_PerfectKeylogger_3{
	meta:
		description = "MonitoringTool:Win32/PerfectKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 00 70 00 6b 00 2e 00 64 00 61 00 74 00 00 00 77 00 65 00 62 00 2e 00 64 00 61 00 74 00 00 00 62 00 70 00 6b 00 63 00 68 00 2e 00 64 00 61 00 74 00 } //01 00 
		$a_01_1 = {6b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 73 00 2e 00 68 00 74 00 6d 00 6c 00 00 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 73 00 2e 00 68 00 74 00 6d 00 6c 00 00 00 63 00 68 00 61 00 74 00 73 00 2e 00 68 00 74 00 6d 00 6c 00 } //01 00 
		$a_01_2 = {34 00 29 00 20 00 43 00 6c 00 69 00 63 00 6b 00 20 00 22 00 53 00 68 00 6f 00 77 00 20 00 65 00 6e 00 74 00 69 00 72 00 65 00 20 00 6c 00 6f 00 67 00 22 00 } //01 00  4) Click "Show entire log"
		$a_01_3 = {4c 00 6f 00 67 00 20 00 75 00 70 00 6c 00 6f 00 61 00 64 00 20 00 64 00 61 00 74 00 65 00 3a 00 20 00 25 00 73 00 } //01 00  Log upload date: %s
		$a_01_4 = {42 00 50 00 4b 00 5f 00 33 00 32 00 5f 00 36 00 34 00 } //01 00  BPK_32_64
		$a_01_5 = {25 00 30 00 32 00 64 00 2d 00 25 00 30 00 32 00 64 00 2d 00 25 00 30 00 32 00 64 00 2d 00 25 00 30 00 32 00 64 00 2d 00 25 00 30 00 32 00 64 00 2d 00 25 00 30 00 32 00 64 00 00 00 2f 00 00 00 5c 00 00 00 2f 00 00 00 2f 00 00 00 2e 00 6a 00 70 00 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_PerfectKeylogger_4{
	meta:
		description = "MonitoringTool:Win32/PerfectKeylogger,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //03 00  SetWindowsHookExA
		$a_01_1 = {45 6e 61 62 6c 65 53 70 65 63 69 61 6c 4b 65 79 73 4c 6f 67 67 69 6e 67 } //03 00  EnableSpecialKeysLogging
		$a_01_2 = {45 6e 61 62 6c 65 4e 54 49 6e 76 69 73 69 62 6c 65 } //01 00  EnableNTInvisible
		$a_01_3 = {77 62 2e 64 6c 6c 00 00 68 6b 2e 64 6c 6c } //01 00 
		$a_01_4 = {74 69 74 6c 65 73 2e 64 61 74 00 61 70 70 73 2e 64 61 74 } //01 00 
		$a_01_5 = {00 70 6b 2e 62 69 6e 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_PerfectKeylogger_5{
	meta:
		description = "MonitoringTool:Win32/PerfectKeylogger,SIGNATURE_TYPE_PEHSTR,20 00 20 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 65 74 75 70 3d 72 69 6e 73 74 2e 65 78 65 } //0a 00  Setup=rinst.exe
		$a_01_1 = {61 70 70 73 2e 64 61 74 00 00 00 00 70 6b 2e 62 69 6e } //0a 00 
		$a_01_2 = {50 65 72 66 65 63 74 20 4b 65 79 6c 6f 67 67 65 72 } //0a 00  Perfect Keylogger
		$a_01_3 = {25 41 50 50 44 41 54 41 25 5c 42 50 4b 5c } //0a 00  %APPDATA%\BPK\
		$a_01_4 = {77 65 62 2e 64 61 74 00 62 70 6b 63 68 2e 64 61 74 } //01 00 
		$a_01_5 = {76 77 2e 65 78 65 } //01 00  vw.exe
		$a_01_6 = {77 62 2e 64 6c 6c } //01 00  wb.dll
		$a_01_7 = {68 6b 2e 64 6c 6c } //00 00  hk.dll
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_PerfectKeylogger_6{
	meta:
		description = "MonitoringTool:Win32/PerfectKeylogger,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 0c 00 00 03 00 "
		
	strings :
		$a_01_0 = {62 70 6b 2e 63 68 6d } //03 00  bpk.chm
		$a_01_1 = {62 70 6b 2e 64 61 74 } //03 00  bpk.dat
		$a_01_2 = {72 69 6e 73 74 2e 65 78 65 } //03 00  rinst.exe
		$a_01_3 = {42 50 4b 20 4d 61 69 6e 20 57 69 6e 64 6f 77 } //02 00  BPK Main Window
		$a_01_4 = {50 4b 4c 20 57 69 6e 64 6f 77 } //02 00  PKL Window
		$a_01_5 = {70 6b 2e 62 69 6e } //02 00  pk.bin
		$a_01_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 6c 61 7a 69 6e 67 74 6f 6f 6c 73 2e 63 6f 6d } //03 00  http://www.blazingtools.com
		$a_01_7 = {62 73 64 68 6f 6f 6b 73 2e 64 6c 6c } //03 00  bsdhooks.dll
		$a_01_8 = {50 65 72 66 65 63 74 20 4b 65 79 6c 6f 67 67 65 72 } //03 00  Perfect Keylogger
		$a_01_9 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 42 50 4b } //01 00  Program Files\BPK
		$a_01_10 = {50 43 20 61 6e 64 20 49 6e 74 65 72 6e 65 74 20 73 75 72 76 65 69 6c 6c 61 6e 63 65 } //01 00  PC and Internet surveillance
		$a_01_11 = {53 6f 66 74 77 61 72 65 5c 42 6c 61 7a 69 6e 67 20 54 6f 6f 6c 73 } //00 00  Software\Blazing Tools
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_PerfectKeylogger_7{
	meta:
		description = "MonitoringTool:Win32/PerfectKeylogger,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 07 00 00 04 00 "
		
	strings :
		$a_01_0 = {77 62 2e 64 6c 6c 00 00 68 6b 2e 64 6c 6c 00 00 72 2e 65 78 65 00 00 00 2e 65 78 65 00 00 00 00 6b 77 2e 64 61 74 00 00 69 6e 73 74 2e 64 61 74 00 00 00 00 6d 63 2e 64 61 74 00 00 74 69 74 6c 65 73 2e 64 61 74 00 00 61 70 70 73 2e 64 61 74 00 00 00 00 70 6b 2e 62 69 6e 00 00 } //04 00 
		$a_01_1 = {00 62 70 6b 2e 64 61 74 00 77 65 62 2e 64 61 74 00 62 70 6b 63 68 2e 64 61 74 00 00 } //02 00 
		$a_01_2 = {4c 6f 67 20 75 70 6c 6f 61 64 20 64 61 74 65 3a 20 25 73 0d 0a 54 69 6d 65 3a 20 25 73 0d 0a 43 6f 6d 70 75 74 65 72 3a 20 25 73 0d 0a 49 50 20 61 64 64 72 65 73 73 3a 20 25 73 0d 0a 55 73 65 72 3a 20 25 73 0d } //02 00 
		$a_01_3 = {42 50 4b 20 49 45 20 46 69 6c 65 20 55 70 6c 6f 61 64 65 72 20 43 6c 61 73 73 } //02 00  BPK IE File Uploader Class
		$a_01_4 = {50 4b 4c 20 57 69 6e 64 6f 77 } //01 00  PKL Window
		$a_01_5 = {53 68 6f 77 20 65 6e 74 69 72 65 20 6c 6f 67 } //01 00  Show entire log
		$a_01_6 = {6b 65 79 73 74 72 6f 6b 65 73 2e 68 74 6d 6c } //00 00  keystrokes.html
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_PerfectKeylogger_8{
	meta:
		description = "MonitoringTool:Win32/PerfectKeylogger,SIGNATURE_TYPE_PEHSTR,19 00 19 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //0a 00  IsDebuggerPresent
		$a_01_1 = {46 49 58 43 4c 4f 43 4b } //02 00  FIXCLOCK
		$a_01_2 = {50 00 65 00 72 00 66 00 65 00 63 00 74 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 } //02 00  Perfect Keylogger 
		$a_01_3 = {62 00 6c 00 61 00 7a 00 69 00 6e 00 67 00 74 00 6f 00 6f 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00 00 00 } //02 00 
		$a_01_4 = {50 00 65 00 72 00 66 00 65 00 63 00 74 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 21 00 } //01 00  Perfect Keylogger!
		$a_01_5 = {73 00 63 00 72 00 65 00 65 00 6e 00 20 00 63 00 61 00 70 00 74 00 75 00 72 00 65 00 20 00 28 00 73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 29 00 } //01 00  screen capture (screenshot)
		$a_01_6 = {63 00 6c 00 65 00 61 00 72 00 20 00 6c 00 6f 00 67 00 } //01 00  clear log
		$a_01_7 = {26 00 53 00 74 00 65 00 61 00 6c 00 74 00 68 00 } //01 00  &Stealth
		$a_01_8 = {6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 27 00 73 00 20 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 } //00 00  keylogger's startup
	condition:
		any of ($a_*)
 
}