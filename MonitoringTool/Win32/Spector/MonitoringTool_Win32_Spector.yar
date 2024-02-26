
rule MonitoringTool_Win32_Spector{
	meta:
		description = "MonitoringTool:Win32/Spector,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {43 68 65 63 6b 44 6f 63 41 4f 4c 3a 47 65 74 41 64 64 72 65 73 73 65 73 } //02 00  CheckDocAOL:GetAddresses
		$a_01_1 = {25 32 32 61 63 74 69 6f 6e 25 32 32 25 33 41 25 32 32 53 65 6e 64 4d 65 73 73 61 67 65 25 32 32 } //03 00  %22action%22%3A%22SendMessage%22
		$a_01_2 = {43 68 65 63 6b 44 6f 63 47 4d 61 69 6c 3a 43 68 65 63 6b 44 6f 63 45 6d 61 69 6c } //00 00  CheckDocGMail:CheckDocEmail
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_Spector_2{
	meta:
		description = "MonitoringTool:Win32/Spector,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {57 61 6e 74 50 4f 53 54 47 4d 61 69 6c 90 02 30 6d 61 69 6c 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 90 00 } //01 00 
		$a_02_1 = {57 61 6e 74 50 4f 53 54 4f 57 41 90 02 30 2f 6f 77 61 2f 61 75 74 68 2f 6f 77 61 61 75 74 68 2e 64 6c 6c 90 00 } //01 00 
		$a_02_2 = {57 61 6e 74 50 4f 53 54 59 61 68 6f 6f 90 02 30 6d 61 69 6c 2e 79 61 68 6f 6f 2e 90 00 } //01 00 
		$a_00_3 = {53 65 6e 64 4d 65 73 73 61 67 65 00 61 63 74 69 6f 6e 00 00 72 65 71 75 65 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_Spector_3{
	meta:
		description = "MonitoringTool:Win32/Spector,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 90 02 30 49 41 6c 6c 6f 63 00 90 00 } //01 00 
		$a_01_1 = {48 6f 74 4d 61 69 6c 00 59 61 68 6f 6f 00 00 00 53 65 6e 64 00 00 00 00 52 65 63 65 69 76 65 00 6e 63 61 6c 72 70 63 00 25 73 5f 25 73 5f 25 64 00 00 00 00 74 69 64 70 69 6d 00 } //01 00 
		$a_01_2 = {53 74 61 72 74 52 65 63 6f 72 64 00 53 74 6f 70 52 65 63 6f 72 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_Spector_4{
	meta:
		description = "MonitoringTool:Win32/Spector,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 68 69 6c 6c 69 70 2d 2d 47 74 56 65 72 66 79 53 74 6e 67 2d 2d 50 6f 77 65 72 73 } //01 00  Phillip--GtVerfyStng--Powers
		$a_01_1 = {50 72 6f 63 65 73 73 4b 65 79 73 74 72 6f 6b 65 46 69 6c 65 31 } //01 00  ProcessKeystrokeFile1
		$a_01_2 = {53 65 74 46 69 6c 65 54 69 6d 65 54 6f 4b 65 72 6e 65 6c 73 5f 48 61 6e 64 6c 65 } //01 00  SetFileTimeToKernels_Handle
		$a_01_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 45 76 65 6e 74 4c 6f 67 5c 41 70 70 6c 69 63 61 74 69 6f 6e 5c } //00 00  SYSTEM\CurrentControlSet\Services\EventLog\Application\
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_Spector_5{
	meta:
		description = "MonitoringTool:Win32/Spector,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 65 63 6f 72 64 65 72 3a 3a 43 68 61 74 41 64 64 } //03 00  Recorder::ChatAdd
		$a_01_1 = {50 72 6f 63 65 73 73 43 68 61 74 45 76 65 6e 74 3a 20 50 72 6f 63 65 73 73 20 64 61 74 61 20 6e 6f 74 20 66 6f 75 6e 64 20 66 6f 72 20 70 72 6f 63 65 73 73 20 30 78 25 70 } //02 00  ProcessChatEvent: Process data not found for process 0x%p
		$a_01_2 = {50 72 6f 63 65 73 73 50 6f 72 74 45 76 65 6e 74 3a 20 50 72 6f 63 65 73 73 20 64 61 74 61 20 6e 6f 74 20 66 6f 75 6e 64 20 66 6f 72 20 70 72 6f 63 65 73 73 20 30 78 25 70 } //01 00  ProcessPortEvent: Process data not found for process 0x%p
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //00 00  CreateToolhelp32Snapshot
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_Spector_6{
	meta:
		description = "MonitoringTool:Win32/Spector,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6d 73 6e 65 74 70 61 63 6b 65 74 74 79 70 65 } //0a 00  msnetpackettype
		$a_00_1 = {73 70 65 63 74 6f 72 } //01 00  spector
		$a_01_2 = {53 74 61 72 74 52 65 63 6f 72 64 00 53 74 6f 70 52 65 63 6f 72 64 00 } //01 00 
		$a_01_3 = {2d 2d 47 74 56 65 72 66 79 53 74 6e 67 2d 2d } //01 00  --GtVerfyStng--
		$a_00_4 = {41 67 65 6e 74 53 65 74 74 69 6e 67 73 2e 43 61 70 74 75 72 65 4b 65 79 53 74 72 6f 6b 65 73 } //01 00  AgentSettings.CaptureKeyStrokes
		$a_00_5 = {53 74 61 72 74 52 65 63 6f 72 64 69 6e 67 57 69 74 68 57 69 6e 64 6f 77 73 } //01 00  StartRecordingWithWindows
		$a_00_6 = {54 61 6b 65 4b 65 79 77 6f 72 64 53 63 72 65 65 6e 73 68 6f 74 } //01 00  TakeKeywordScreenshot
		$a_00_7 = {73 74 65 61 6c 74 68 } //00 00  stealth
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_Spector_7{
	meta:
		description = "MonitoringTool:Win32/Spector,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 04 00 "
		
	strings :
		$a_03_0 = {84 c9 75 f6 66 8b 0d 90 01 04 66 89 08 8a 15 90 01 04 88 50 02 8b 07 56 8b cf 8b 50 0c ff d2 6a 02 6a 00 6a 00 8b 5d e4 53 ff 15 90 01 04 8b c6 8d 48 01 90 00 } //04 00 
		$a_03_1 = {05 d8 22 00 00 50 ff 15 90 01 04 89 86 dc 01 00 00 3b c3 74 90 01 01 68 90 01 04 50 ff 15 90 01 04 89 86 90 01 04 8d be 90 01 04 57 68 46 23 00 00 6a 01 68 23 56 14 23 ff d0 90 00 } //01 00 
		$a_01_2 = {77 65 62 6c 6f 63 63 68 65 63 6b } //01 00  webloccheck
		$a_01_3 = {2d 2d 47 74 56 65 72 66 79 53 74 6e 67 2d 2d } //01 00  --GtVerfyStng--
		$a_01_4 = {6d 73 6e 65 74 70 61 63 6b 65 74 74 79 70 65 } //01 00  msnetpackettype
		$a_01_5 = {77 65 62 6c 6f 63 61 6f 6c 73 65 } //01 00  weblocaolse
		$a_01_6 = {77 6f 77 73 6b 79 70 65 } //01 00  wowskype
		$a_01_7 = {6b 62 64 77 64 6d 64 65 76 } //01 00  kbdwdmdev
		$a_01_8 = {77 65 62 6d 61 70 69 62 6f 78 } //00 00  webmapibox
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_Spector_8{
	meta:
		description = "MonitoringTool:Win32/Spector,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {46 41 43 45 42 4f 4f 4b 5f 48 54 54 50 00 90 05 06 01 00 42 4f 4e 4a 4f 55 52 00 90 05 06 01 00 4d 59 53 50 41 43 45 5f 48 54 54 50 90 00 } //01 00 
		$a_03_1 = {49 43 51 5f 48 4c 00 90 05 06 01 00 41 49 4d 5f 4d 45 45 42 4f 00 90 05 06 01 00 59 41 48 4f 4f 5f 4d 45 45 42 4f 00 90 05 05 01 00 47 54 41 4c 4b 5f 4d 45 45 42 4f 00 90 05 06 01 00 4d 53 4e 5f 4d 45 45 42 4f 00 90 05 06 01 00 49 43 51 5f 4d 45 45 42 4f 00 90 05 06 01 00 4a 41 42 42 45 52 5f 4d 45 45 42 4f 00 90 05 06 01 00 55 4e 4b 4e 4f 57 4e 5f 4d 45 45 42 4f 90 00 } //01 00 
		$a_03_2 = {41 73 74 72 61 5f 54 72 69 6c 6c 69 61 6e 00 90 05 06 01 00 41 49 4d 5f 54 72 69 6c 6c 69 61 6e 00 90 05 06 01 00 46 61 63 65 62 6f 6f 6b 5f 54 72 69 6c 6c 69 61 6e 00 90 05 06 01 00 47 54 74 61 6c 6b 5f 54 72 69 6c 6c 69 61 6e 90 00 } //01 00 
		$a_03_3 = {45 4e 44 5f 53 45 53 53 49 4f 4e 00 90 05 06 01 00 53 54 41 52 54 5f 41 43 54 49 56 49 54 59 00 90 05 06 01 00 45 4e 44 5f 41 43 54 49 56 49 54 59 00 90 05 06 01 00 53 54 41 52 54 5f 49 4e 41 43 54 49 56 49 54 59 90 00 } //01 00 
		$a_01_4 = {43 61 6c 6c 69 6e 67 20 54 65 72 6d 43 6c 69 65 6e 74 20 66 72 6f 6d 20 53 65 72 76 69 63 65 53 70 65 63 74 6f 72 3a 3a 52 65 69 6e 69 74 69 61 6c 69 7a 65 } //01 00  Calling TermClient from ServiceSpector::Reinitialize
		$a_01_5 = {5c 5c 2e 5c 70 69 70 65 5c 53 70 65 63 74 6f 72 4c 69 76 65 4c 6f 67 } //00 00  \\.\pipe\SpectorLiveLog
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_Spector_9{
	meta:
		description = "MonitoringTool:Win32/Spector,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 70 65 63 74 6f 72 } //01 00  spector
		$a_01_1 = {48 65 6c 70 53 74 61 72 74 52 65 63 6f 72 64 } //01 00  HelpStartRecord
		$a_01_2 = {48 65 6c 70 53 74 6f 70 52 65 63 6f 72 64 } //01 00  HelpStopRecord
		$a_01_3 = {48 65 6c 70 53 74 6f 70 48 6f 6f 6b } //01 00  HelpStopHook
		$a_01_4 = {48 65 6c 70 53 65 74 48 6f 6f 6b } //01 00  HelpSetHook
		$a_01_5 = {53 74 61 72 74 49 6e 74 65 72 6e 65 74 } //01 00  StartInternet
		$a_01_6 = {53 74 6f 70 49 6e 74 65 72 6e 65 74 } //01 00  StopInternet
		$a_01_7 = {4d 6f 6e 69 74 6f 72 44 43 45 45 76 65 6e 74 73 } //01 00  MonitorDCEEvents
		$a_01_8 = {49 6e 61 63 74 69 76 69 74 79 54 69 6d 65 72 50 72 6f 63 } //00 00  InactivityTimerProc
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_Spector_10{
	meta:
		description = "MonitoringTool:Win32/Spector,SIGNATURE_TYPE_PEHSTR,16 00 15 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 42 38 44 45 38 36 33 2d 30 35 36 31 2d 34 66 66 64 2d 39 42 38 36 2d 35 42 41 32 45 39 34 31 42 41 35 32 } //0a 00  CB8DE863-0561-4ffd-9B86-5BA2E941BA52
		$a_01_1 = {5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 } //01 00  \.\PhysicalDrive%d
		$a_01_2 = {53 4d 54 50 50 4f 50 00 57 65 62 4d 61 69 6c 00 50 6c 61 69 6e 54 65 78 74 } //01 00 
		$a_01_3 = {53 74 61 72 74 52 65 63 6f 72 64 69 6e 67 57 69 74 68 57 69 6e 64 6f 77 73 } //01 00  StartRecordingWithWindows
		$a_01_4 = {54 61 6b 65 4b 65 79 77 6f 72 64 53 63 72 65 65 6e 73 68 6f 74 } //01 00  TakeKeywordScreenshot
		$a_01_5 = {41 67 65 6e 74 53 65 74 74 69 6e 67 73 2e 43 61 70 74 75 72 65 4b 65 79 53 74 72 6f 6b 65 73 } //01 00  AgentSettings.CaptureKeyStrokes
		$a_01_6 = {53 65 74 46 69 6c 65 54 69 6d 65 54 6f 4b 65 72 6e 65 6c 73 5f 50 61 74 68 } //00 00  SetFileTimeToKernels_Path
	condition:
		any of ($a_*)
 
}