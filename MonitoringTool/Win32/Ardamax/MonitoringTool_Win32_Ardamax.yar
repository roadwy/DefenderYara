
rule MonitoringTool_Win32_Ardamax{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {ba 03 01 00 00 75 12 8b 41 08 d1 e8 40 8d 71 0c 3b c2 } //1
		$a_02_1 = {56 85 c9 74 0b 8b 71 44 3b 35 90 01 04 74 0c 8b 31 85 f6 74 12 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule MonitoringTool_Win32_Ardamax_2{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 4b 4c 4d 57 00 } //2 䭁䵌W
		$a_01_1 = {41 4b 4c 2e 30 30 33 00 73 66 78 5f 6d 61 69 6e 00 } //2
		$a_02_2 = {55 8b ec 51 51 56 57 68 90 01 02 00 10 33 ff 57 ff 15 90 01 02 00 10 3b c7 74 0e 57 57 68 65 80 00 00 50 ff 15 90 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_02_2  & 1)*2) >=6
 
}
rule MonitoringTool_Win32_Ardamax_3{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 0e 53 53 68 65 80 00 00 50 ff 15 90 01 04 90 02 01 68 90 01 04 be 04 01 00 00 56 ff 15 90 01 04 8b 4d 08 8b 01 ff 90 03 01 04 10 50 90 01 01 53 68 80 00 00 00 6a 03 53 6a 01 68 00 00 00 80 50 ff 15 90 01 04 90 03 07 07 a3 90 01 04 83 f8 ff 83 f8 ff a3 90 01 04 75 04 33 c0 eb 61 57 53 8d 4d f8 51 6a 04 8d 4d fc 51 50 ff 15 90 01 04 8b 45 fc 2b c3 bf 90 01 04 74 0d 48 75 12 56 57 ff 15 90 01 04 eb 08 56 57 ff 15 90 01 04 68 90 01 04 57 ff 15 90 01 04 53 57 ff 15 90 01 04 5f e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule MonitoringTool_Win32_Ardamax_4{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //2 UnhookWindowsHookEx
		$a_01_1 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //2 SetWindowsHookExA
		$a_00_2 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //2 ZwQuerySystemInformation
		$a_01_3 = {2e 30 30 37 00 48 6f 6f 6b 00 55 6e 68 6f 6f 6b 00 } //2
		$a_01_4 = {68 38 20 00 10 68 2c 20 00 10 ff 15 0c 20 00 10 50 ff 15 08 20 00 10 85 c0 a3 08 30 00 10 74 41 6a 00 6a 06 68 18 30 00 10 50 6a ff ff 15 04 20 00 10 6a 00 6a 06 68 10 30 00 10 ff 35 08 30 00 10 c6 05 10 30 00 10 68 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}
rule MonitoringTool_Win32_Ardamax_5{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {fa ee c2 99 ea 44 7c 06 } //1
		$a_01_1 = {90 90 8b 45 08 a3 04 f0 00 01 a1 94 dc 00 01 85 c0 74 2e 68 04 01 00 00 ff 75 0c 68 08 f0 00 01 ff d0 a1 9c dc 00 01 85 c0 74 16 6a 00 ff 35 78 dc 00 01 68 0d 2f 00 01 6a 04 ff d0 a3 00 f0 00 01 90 90 } //1
		$a_01_2 = {be 1a 00 00 80 eb 32 85 c0 7c 34 53 57 e8 23 ff ff ff 59 59 85 c0 75 03 ff 45 f8 } //1
		$a_01_3 = {90 90 33 c0 ba 38 a1 00 01 39 45 08 75 0b 8b 4d 0c 8b 41 08 8d 51 0c eb 0f 83 7d 08 01 75 18 8b 45 0c 8d 50 14 8b 40 10 d1 e8 40 3d 03 01 00 00 72 05 b8 04 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule MonitoringTool_Win32_Ardamax_6{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //2 UnhookWindowsHookEx
		$a_01_1 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //2 SetWindowsHookExA
		$a_00_2 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //2 ZwQuerySystemInformation
		$a_01_3 = {2e 30 30 37 00 48 6f 6f 6b 00 55 6e 68 6f 6f 6b 00 } //2
		$a_02_4 = {68 48 20 00 10 68 3c 20 00 10 ff 15 14 20 00 10 50 ff 15 10 20 00 10 85 c0 a3 34 30 00 10 74 5b 56 be 14 30 00 10 56 ff 15 08 20 00 10 6a 00 6a 06 68 2c 30 00 10 ff 35 34 30 00 10 6a ff ff 15 0c 20 00 10 6a 00 6a 06 68 0c 30 00 10 ff 35 34 30 00 10 90 02 30 c6 05 0c 30 00 10 68 90 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*2+(#a_02_4  & 1)*2) >=10
 
}
rule MonitoringTool_Win32_Ardamax_7{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //2 UnhookWindowsHookEx
		$a_01_1 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //2 SetWindowsHookExA
		$a_00_2 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //2 ZwQuerySystemInformation
		$a_01_3 = {2e 30 30 37 00 48 6f 6f 6b 00 55 6e 68 6f 6f 6b 00 } //2
		$a_02_4 = {68 4c 20 00 10 68 40 20 00 10 ff 15 18 20 00 10 50 ff 15 14 20 00 10 85 c0 a3 34 30 00 10 74 5d 56 be 14 30 00 10 56 ff 15 08 20 00 10 6a 00 6a 06 68 2c 30 00 10 ff 35 34 30 00 10 6a ff ff 15 10 20 00 10 6a 00 6a 06 68 0c 30 00 10 ff 35 34 30 00 10 90 02 30 c6 05 0c 30 00 10 68 90 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*2+(#a_02_4  & 1)*2) >=10
 
}
rule MonitoringTool_Win32_Ardamax_8{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {22 00 00 00 00 41 4b 4c 2e 30 30 33 00 73 66 78 5f 6d 61 69 6e } //1
		$a_01_1 = {23 00 00 00 00 41 4b 4c 2e 30 30 33 00 73 66 78 5f 6d 61 69 6e } //1
		$a_01_2 = {5c 00 32 00 38 00 34 00 36 00 33 00 5c 00 00 00 41 00 4b 00 4c 00 4d 00 57 00 00 00 } //1
		$a_01_3 = {5c 00 53 00 79 00 73 00 33 00 32 00 5c 00 00 00 41 00 4b 00 4c 00 4d 00 57 00 00 00 } //1
		$a_01_4 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 57 00 f4 01 47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 57 00 00 d6 01 47 65 74 54 65 6d 70 50 61 74 68 57 00 00 } //1
		$a_00_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //1 ShellExecuteW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}
rule MonitoringTool_Win32_Ardamax_9{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 43 50 61 73 73 77 6f 72 64 45 6e 74 65 72 44 6c 67 40 40 } //65436 .?AVCPasswordEnterDlg@@
		$a_01_1 = {fa ee c2 99 ea 44 7c 06 } //1
		$a_03_2 = {ff 76 04 ff 36 ff 75 08 e8 90 01 04 83 c4 0c ff 76 04 8b ce ff 75 08 e8 90 01 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 5e 5d c2 04 00 90 00 } //1
		$a_01_3 = {90 90 8b 7d 0c 8b 4d 08 8d 45 fc 50 be 9d 00 00 00 56 57 e8 d2 fe ff ff 85 c0 7c 1e 39 75 fc 75 19 ff 37 e8 e9 fe ff ff 59 3b 47 04 75 0c 57 e8 1e ff ff ff 33 c0 59 40 eb 0a } //1
		$a_01_4 = {90 90 33 d2 33 f6 39 55 0c 7e 19 83 fa 04 72 02 33 d2 8b 45 08 8a 4c 17 08 03 c6 30 08 42 46 3b 75 0c 7c e7 90 90 } //1
	condition:
		((#a_01_0  & 1)*65436+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}
rule MonitoringTool_Win32_Ardamax_10{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_81_0 = {41 52 44 41 4d 41 58 20 4b 45 59 4c 4f 47 47 45 52 20 49 53 20 44 49 53 54 52 49 42 55 54 45 44 20 22 41 53 20 49 53 22 } //1 ARDAMAX KEYLOGGER IS DISTRIBUTED "AS IS"
		$a_81_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 72 64 61 6d 61 78 2e 63 6f 6d 2f 6b 65 79 6c 6f 67 67 65 72 2f } //1 http://www.ardamax.com/keylogger/
		$a_03_2 = {22 6c 7a 6d 61 2e 65 78 65 22 20 22 64 22 20 22 90 01 01 2e 6c 7a 22 20 22 90 03 03 03 41 4b 56 52 45 46 2e 65 78 65 22 90 00 } //1
		$a_81_3 = {5c 41 72 64 61 6d 61 78 20 4b 65 79 6c 6f 67 67 65 72 } //1 \Ardamax Keylogger
		$a_81_4 = {5c 4c 6f 67 20 56 69 65 77 65 72 2e 6c 6e 6b } //1 \Log Viewer.lnk
		$a_81_5 = {4b 65 79 6c 6f 67 67 65 72 20 45 6e 67 69 6e 65 00 } //1
		$a_81_6 = {41 4b 4c 4d 57 00 53 65 74 75 70 20 68 61 73 20 64 65 74 65 63 74 65 64 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=5
 
}
rule MonitoringTool_Win32_Ardamax_11{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {fa ee c2 99 ea 44 7c 06 } //1
		$a_01_1 = {90 90 33 c9 33 f6 39 4d 10 7e 1b 83 f9 0b 7c 02 33 c9 8b 45 0c 8b 55 08 8a 14 11 03 c6 30 10 41 46 3b 75 10 7c e5 90 90 } //1
		$a_01_2 = {8d 44 00 01 85 c0 7e 1d 8b d0 56 33 c9 8b 45 08 8d 04 48 be 34 92 00 00 66 31 30 41 83 f9 32 7c ec 4a 75 e7 5e 5d c3 } //1
		$a_03_3 = {46 46 50 66 8b 46 44 66 03 85 90 01 02 ff ff 0f b7 c0 50 53 ff 15 90 01 04 89 85 e4 fd ff ff 3b c3 0f 84 90 01 02 00 00 50 53 ff 15 90 01 04 3b c3 0f 84 cb 01 00 00 50 ff 15 90 01 04 89 85 90 01 02 ff ff 3b c3 0f 84 90 01 02 00 00 ff b5 90 01 02 ff ff 53 ff 15 90 01 04 03 f8 89 85 90 01 02 ff ff 57 39 9d 90 01 02 ff ff 74 0e ff b5 90 01 02 ff ff e8 90 01 04 59 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule MonitoringTool_Win32_Ardamax_12{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0b 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 7d 08 00 75 16 f7 45 10 00 00 00 80 75 0d ff 75 10 ff 75 0c e8 90 01 04 59 59 ff 75 10 ff 75 0c ff 75 08 ff 35 90 01 04 ff 15 90 01 04 5d c2 0c 00 90 00 } //3
		$a_00_1 = {64 3a 5c 50 72 6f 6a 65 63 74 73 5c 41 4b 4c 5c 6b 68 5c 52 65 6c 65 61 73 65 5c 6b 68 2e 70 64 62 } //1 d:\Projects\AKL\kh\Release\kh.pdb
		$a_01_2 = {53 65 74 57 6e 64 4d 6f 6e 48 6f 6f 6b } //1 SetWndMonHook
		$a_01_3 = {41 64 64 4d 6f 6e 69 74 6f 72 65 64 57 6e 64 } //1 AddMonitoredWnd
		$a_01_4 = {43 6c 65 61 72 4b 65 79 48 6f 6f 6b } //1 ClearKeyHook
		$a_01_5 = {43 6c 65 61 72 57 6e 64 4d 6f 6e 48 6f 6f 6b } //1 ClearWndMonHook
		$a_01_6 = {52 65 6d 6f 76 65 4d 6f 6e 69 74 6f 72 65 64 57 6e 64 } //1 RemoveMonitoredWnd
		$a_01_7 = {53 65 74 4b 65 79 48 6f 6f 6b } //2 SetKeyHook
		$a_01_8 = {55 57 4d 5f 57 4e 44 4d 4f 4e 48 4f 4f 4b 5f 4d 53 47 } //1 UWM_WNDMONHOOK_MSG
		$a_01_9 = {55 57 4d 5f 4b 45 59 48 4f 4f 4b 5f 4d 53 47 2d 39 36 38 43 33 30 34 33 2d 31 31 32 38 2d 34 33 64 63 2d 38 33 41 39 2d 35 35 31 32 32 43 38 44 38 37 43 31 } //3 UWM_KEYHOOK_MSG-968C3043-1128-43dc-83A9-55122C8D87C1
		$a_00_10 = {41 4b 4c 2e 64 6c 6c } //1 AKL.dll
	condition:
		((#a_02_0  & 1)*3+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*2+(#a_01_8  & 1)*1+(#a_01_9  & 1)*3+(#a_00_10  & 1)*1) >=12
 
}
rule MonitoringTool_Win32_Ardamax_13{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd3 00 ffffffd3 00 0a 00 00 "
		
	strings :
		$a_01_0 = {fa ee c2 99 ea 44 7c 06 } //10
		$a_01_1 = {ef 6f c4 0b ff c5 7a 94 } //10
		$a_01_2 = {f8 cc e2 99 e8 66 5c 06 } //10
		$a_01_3 = {10 aa 6e a9 eb be c0 d8 } //10
		$a_01_4 = {40 b7 d8 5a fb 6e af 4a } //10
		$a_03_5 = {8a 54 0d fc 03 c6 30 10 41 46 3b 75 0c 72 e7 5e c9 c2 08 00 90 09 1f 00 55 8b ec 51 56 33 c9 33 f6 c7 45 fc 90 01 04 39 4d 0c 76 19 83 f9 04 72 02 33 c9 8b 45 08 90 00 } //100
		$a_01_6 = {03 d0 83 c0 08 89 55 f8 3b c2 eb 3d 0f b7 00 8b d0 81 e2 ff 0f 00 00 03 d7 3b 55 08 72 23 3b 55 0c 73 1e 25 00 f0 00 00 bb 00 30 00 00 66 3b c3 75 0f 83 7d 10 00 8b 41 04 74 04 01 02 eb 02 29 02 8b 45 fc 40 40 3b 45 f8 } //100
		$a_03_7 = {46 46 50 66 8b 46 44 66 03 85 90 01 02 ff ff 0f b7 c0 50 53 ff 15 90 01 04 89 85 e4 fd ff ff 3b c3 0f 84 90 01 02 00 00 50 53 ff 15 90 01 04 3b c3 0f 84 cb 01 00 00 50 ff 15 90 01 04 89 85 90 01 02 ff ff 3b c3 0f 84 90 01 02 00 00 ff b5 90 01 02 ff ff 53 ff 15 90 01 04 03 f8 89 85 90 01 02 ff ff 57 39 9d 90 01 02 ff ff 74 0e ff b5 90 01 02 ff ff e8 90 01 04 59 90 00 } //1
		$a_03_8 = {74 2e 68 04 01 00 00 ff 75 0c 68 90 01 03 01 ff d0 a1 90 01 03 01 85 c0 74 16 6a 00 ff 35 90 01 03 01 68 90 01 03 01 6a 04 ff d0 a3 90 01 03 01 90 90 90 90 90 09 11 00 90 90 90 90 8b 45 08 a3 90 01 03 01 a1 90 01 03 01 85 c0 90 00 } //1
		$a_03_9 = {71 0c 6a 02 eb 05 ff 71 0c 6a 01 ff 35 90 01 03 01 ff 35 90 01 03 01 ff 15 90 01 03 01 90 90 90 90 90 09 0f 00 90 90 90 90 8b 4d 08 8b 41 08 48 74 0a 48 75 1e ff 90 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_03_5  & 1)*100+(#a_01_6  & 1)*100+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1) >=211
 
}
rule MonitoringTool_Win32_Ardamax_14{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 16 00 00 "
		
	strings :
		$a_00_0 = {41 6c 6c 50 65 72 69 6f 64 } //1 AllPeriod
		$a_00_1 = {22 25 73 22 20 4b 65 79 73 74 72 6f 6b 65 73 20 4c 6f 67 20 66 69 6c 65 20 63 61 6e 6e 6f 74 20 6f 70 65 6e 2e } //1 "%s" Keystrokes Log file cannot open.
		$a_00_2 = {22 25 73 22 20 4b 65 79 73 74 72 6f 6b 65 73 20 4c 6f 67 20 66 69 6c 65 20 63 6f 72 72 75 70 74 65 64 2e } //1 "%s" Keystrokes Log file corrupted.
		$a_00_3 = {22 25 73 22 20 57 65 62 20 4c 6f 67 20 66 69 6c 65 20 63 61 6e 6e 6f 74 20 6f 70 65 6e 2e } //1 "%s" Web Log file cannot open.
		$a_00_4 = {22 25 73 22 20 57 65 62 20 4c 6f 67 20 66 69 6c 65 20 63 6f 72 72 75 70 74 65 64 2e } //1 "%s" Web Log file corrupted.
		$a_00_5 = {48 54 4d 4c 20 46 69 6c 65 20 28 2a 2e 68 74 6d 29 } //1 HTML File (*.htm)
		$a_00_6 = {4b 65 79 73 74 72 6f 6b 65 73 20 4c 6f 67 } //1 Keystrokes Log
		$a_00_7 = {4b 65 79 73 56 69 65 77 } //1 KeysView
		$a_00_8 = {4c 6f 67 20 56 69 65 77 65 72 } //1 Log Viewer
		$a_00_9 = {4c 6f 67 73 20 6e 6f 74 20 66 6f 75 6e 64 2e } //1 Logs not found.
		$a_01_10 = {4e 6f 20 70 61 73 73 77 6f 72 64 20 65 6e 74 65 72 65 64 2e } //1 No password entered.
		$a_00_11 = {4e 6f 20 72 65 63 6f 72 64 73 20 66 6f 75 6e 64 } //1 No records found
		$a_00_12 = {50 61 67 65 20 54 69 74 6c 65 } //1 Page Title
		$a_00_13 = {50 61 67 65 54 69 74 6c 65 4c 65 6e } //1 PageTitleLen
		$a_01_14 = {50 61 73 73 77 6f 72 64 20 69 73 20 6e 6f 74 20 76 61 6c 69 64 2e } //1 Password is not valid.
		$a_00_15 = {53 65 6c 65 63 74 20 61 20 72 65 63 6f 72 64 20 74 6f 20 76 69 65 77 20 66 72 6f 6d 20 74 68 65 20 6c 69 73 74 20 61 62 6f 76 65 2e } //1 Select a record to view from the list above.
		$a_00_16 = {53 65 6c 65 63 74 20 74 68 65 20 66 6f 6c 64 65 72 20 77 69 74 68 20 74 68 65 20 6c 6f 67 73 2e } //1 Select the folder with the logs.
		$a_00_17 = {53 74 6f 72 69 6e 67 20 4b 65 79 73 74 72 6f 6b 65 73 20 4c 6f 67 2e 2e 2e } //1 Storing Keystrokes Log...
		$a_00_18 = {53 74 6f 72 69 6e 67 20 57 65 62 20 4c 6f 67 2e 2e 2e } //1 Storing Web Log...
		$a_01_19 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
		$a_00_20 = {55 6e 6b 6e 6f 77 6e 20 22 25 73 22 20 4b 65 79 73 74 72 6f 6b 65 73 20 4c 6f 67 20 66 69 6c 65 20 66 6f 72 6d 61 74 2e } //1 Unknown "%s" Keystrokes Log file format.
		$a_00_21 = {55 6e 6b 6e 6f 77 6e 20 22 25 73 22 20 57 65 62 20 4c 6f 67 20 66 69 6c 65 20 66 6f 72 6d 61 74 2e } //1 Unknown "%s" Web Log file format.
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_01_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_00_18  & 1)*1+(#a_01_19  & 1)*1+(#a_00_20  & 1)*1+(#a_00_21  & 1)*1) >=22
 
}
rule MonitoringTool_Win32_Ardamax_15{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 0e 00 00 "
		
	strings :
		$a_01_0 = {31 30 43 38 38 42 42 31 45 33 32 39 34 39 37 38 42 39 36 42 42 46 37 44 38 38 31 35 36 38 43 43 } //5 10C88BB1E3294978B96BBF7D881568CC
		$a_00_1 = {53 00 74 00 6f 00 72 00 69 00 6e 00 67 00 20 00 43 00 68 00 61 00 74 00 74 00 72 00 6f 00 6b 00 65 00 73 00 20 00 4c 00 6f 00 67 00 2e 00 2e 00 2e 00 } //2 Storing Chattrokes Log...
		$a_00_2 = {4c 00 6f 00 61 00 64 00 69 00 6e 00 67 00 20 00 4b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 73 00 20 00 4c 00 6f 00 67 00 2e 00 2e 00 2e 00 } //2 Loading Keystrokes Log...
		$a_00_3 = {22 00 25 00 73 00 22 00 20 00 4b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 73 00 20 00 4c 00 6f 00 67 00 20 00 66 00 69 00 6c 00 65 00 20 00 63 00 61 00 6e 00 6e 00 6f 00 74 00 20 00 6f 00 70 00 65 00 6e 00 2e 00 } //2 "%s" Keystrokes Log file cannot open.
		$a_00_4 = {22 00 25 00 73 00 22 00 20 00 4b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 73 00 20 00 4c 00 6f 00 67 00 20 00 66 00 69 00 6c 00 65 00 20 00 63 00 6f 00 72 00 72 00 75 00 70 00 74 00 65 00 64 00 2e 00 } //2 "%s" Keystrokes Log file corrupted.
		$a_00_5 = {55 00 6e 00 6b 00 6e 00 6f 00 77 00 6e 00 20 00 22 00 25 00 73 00 22 00 20 00 4b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 73 00 20 00 4c 00 6f 00 67 00 20 00 66 00 69 00 6c 00 65 00 20 00 66 00 6f 00 72 00 6d 00 61 00 74 00 2e 00 } //2 Unknown "%s" Keystrokes Log file format.
		$a_00_6 = {46 00 69 00 6c 00 74 00 65 00 72 00 69 00 6e 00 67 00 20 00 4b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 73 00 20 00 4c 00 6f 00 67 00 2e 00 2e 00 2e 00 } //2 Filtering Keystrokes Log...
		$a_00_7 = {53 00 74 00 6f 00 72 00 69 00 6e 00 67 00 20 00 4b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 73 00 20 00 4c 00 6f 00 67 00 2e 00 2e 00 2e 00 } //2 Storing Keystrokes Log...
		$a_00_8 = {4c 00 6f 00 61 00 64 00 69 00 6e 00 67 00 20 00 57 00 65 00 62 00 20 00 4c 00 6f 00 67 00 2e 00 2e 00 2e 00 } //2 Loading Web Log...
		$a_00_9 = {22 00 25 00 73 00 22 00 20 00 57 00 65 00 62 00 20 00 4c 00 6f 00 67 00 20 00 66 00 69 00 6c 00 65 00 20 00 63 00 61 00 6e 00 6e 00 6f 00 74 00 20 00 6f 00 70 00 65 00 6e 00 2e 00 } //2 "%s" Web Log file cannot open.
		$a_00_10 = {22 00 25 00 73 00 22 00 20 00 57 00 65 00 62 00 20 00 4c 00 6f 00 67 00 20 00 66 00 69 00 6c 00 65 00 20 00 63 00 6f 00 72 00 72 00 75 00 70 00 74 00 65 00 64 00 2e 00 } //2 "%s" Web Log file corrupted.
		$a_00_11 = {55 00 6e 00 6b 00 6e 00 6f 00 77 00 6e 00 20 00 22 00 25 00 73 00 22 00 20 00 57 00 65 00 62 00 20 00 4c 00 6f 00 67 00 20 00 66 00 69 00 6c 00 65 00 20 00 66 00 6f 00 72 00 6d 00 61 00 74 00 2e 00 } //2 Unknown "%s" Web Log file format.
		$a_00_12 = {46 00 69 00 6c 00 74 00 65 00 72 00 69 00 6e 00 67 00 20 00 57 00 65 00 62 00 20 00 4c 00 6f 00 67 00 2e 00 2e 00 2e 00 } //2 Filtering Web Log...
		$a_00_13 = {53 00 74 00 6f 00 72 00 69 00 6e 00 67 00 20 00 57 00 65 00 62 00 20 00 4c 00 6f 00 67 00 2e 00 2e 00 2e 00 } //2 Storing Web Log...
	condition:
		((#a_01_0  & 1)*5+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*2+(#a_00_9  & 1)*2+(#a_00_10  & 1)*2+(#a_00_11  & 1)*2+(#a_00_12  & 1)*2+(#a_00_13  & 1)*2) >=31
 
}
rule MonitoringTool_Win32_Ardamax_16{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 14 00 00 "
		
	strings :
		$a_01_0 = {50 61 73 73 77 6f 72 64 20 69 73 20 6e 6f 74 20 76 61 6c 69 64 2e } //1 Password is not valid.
		$a_01_1 = {4e 6f 20 70 61 73 73 77 6f 72 64 20 65 6e 74 65 72 65 64 2e } //1 No password entered.
		$a_01_2 = {50 61 73 73 77 6f 72 64 20 70 72 6f 74 65 63 74 69 6f 6e 20 28 53 65 63 75 72 69 74 79 20 50 61 67 65 29 20 69 73 20 6e 6f 74 20 61 63 74 69 76 65 2e } //1 Password protection (Security Page) is not active.
		$a_01_3 = {57 68 65 6e 20 73 6f 6d 65 6f 6e 65 20 63 6c 69 63 6b 73 20 22 25 73 22 2c } //1 When someone clicks "%s",
		$a_01_4 = {4e 6f 20 6d 65 74 68 6f 64 20 66 6f 72 20 73 65 6e 64 69 6e 67 20 6c 6f 67 73 20 69 73 20 73 65 6c 65 63 74 65 64 2e } //1 No method for sending logs is selected.
		$a_01_5 = {59 6f 75 20 68 61 76 65 20 25 69 20 64 61 79 28 73 29 20 6c 65 66 74 } //1 You have %i day(s) left
		$a_01_6 = {54 68 65 20 41 72 64 61 6d 61 78 20 4b 65 79 6c 6f 67 67 65 72 20 74 65 73 74 20 46 54 50 20 64 65 6c 69 76 65 72 79 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 6c 65 74 65 64 20 73 75 63 63 65 73 66 75 6c 6c 79 2e } //1 The Ardamax Keylogger test FTP delivery has been completed succesfully.
		$a_01_7 = {54 68 65 20 41 72 64 61 6d 61 78 20 4b 65 79 6c 6f 67 67 65 72 20 74 65 73 74 20 65 2d 6d 61 69 6c 20 64 65 6c 69 76 65 72 79 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 6c 65 74 65 64 20 73 75 63 63 65 73 66 75 6c 6c 79 2e } //1 The Ardamax Keylogger test e-mail delivery has been completed succesfully.
		$a_01_8 = {54 68 65 20 22 4c 61 75 6e 63 68 20 61 74 20 57 69 6e 64 6f 77 73 20 73 74 61 72 74 75 70 22 20 6f 70 74 69 6f 6e 20 28 4f 70 74 69 6f 6e 73 20 50 61 67 65 29 20 69 73 20 64 69 73 61 62 6c 65 64 2e 20 54 68 65 20 6b 65 79 6c 6f 67 67 65 72 20 77 69 6c 6c 20 6e 6f 74 20 62 65 20 6c 61 75 6e 63 68 65 64 20 77 68 65 6e 20 57 69 6e 64 6f 77 73 20 69 73 20 73 74 61 72 74 65 64 2e } //1 The "Launch at Windows startup" option (Options Page) is disabled. The keylogger will not be launched when Windows is started.
		$a_01_9 = {54 68 69 73 20 69 73 20 61 20 74 65 73 74 20 6f 66 20 74 68 65 20 41 72 64 61 6d 61 78 20 4b 65 79 6c 6f 67 67 65 72 2e } //1 This is a test of the Ardamax Keylogger.
		$a_01_10 = {55 57 4d 5f 4b 45 59 48 4f 4f 4b 5f 4d 53 47 2d 39 36 38 43 33 30 34 33 2d 31 31 32 38 2d 34 33 64 63 2d 38 33 41 39 2d 35 35 31 32 32 43 38 44 38 37 43 31 } //1 UWM_KEYHOOK_MSG-968C3043-1128-43dc-83A9-55122C8D87C1
		$a_01_11 = {41 4b 4c 4d 57 } //1 AKLMW
		$a_01_12 = {7b 31 42 46 39 30 44 41 37 2d 42 34 32 34 2d 34 33 62 66 2d 41 45 42 41 2d 41 43 45 34 34 32 41 34 44 34 32 39 7d } //1 {1BF90DA7-B424-43bf-AEBA-ACE442A4D429}
		$a_01_13 = {54 68 65 20 22 48 69 64 65 20 74 68 65 20 70 72 6f 67 72 61 6d 20 66 72 6f 6d 20 57 69 6e 64 6f 77 73 20 73 74 61 72 74 75 70 20 6c 69 73 74 22 20 6f 70 74 69 6f 6e 20 69 73 20 65 6e 61 62 6c 65 64 20 28 49 6e 76 69 73 69 62 69 6c 69 74 79 20 50 61 67 65 29 2e 20 49 66 20 74 68 65 20 63 6f 6d 70 75 74 65 72 20 69 73 20 6e 6f 74 20 73 68 75 74 20 64 6f 77 6e 20 63 6f 72 72 65 63 74 6c 79 20 6f 72 20 69 66 20 74 68 65 72 65 20 69 73 20 61 20 73 79 73 74 65 6d 20 66 61 69 6c 75 72 65 2c 20 74 68 65 20 6b 65 79 6c 6f 67 67 65 72 20 77 69 6c 6c 20 6e 6f 74 20 62 65 20 73 74 61 72 74 65 64 20 74 6f 67 65 74 68 65 72 20 77 69 74 68 20 57 69 6e 64 6f 77 73 2e } //1 The "Hide the program from Windows startup list" option is enabled (Invisibility Page). If the computer is not shut down correctly or if there is a system failure, the keylogger will not be started together with Windows.
		$a_01_14 = {43 6c 65 61 72 4b 65 79 48 6f 6f 6b } //1 ClearKeyHook
		$a_01_15 = {53 65 74 4b 65 79 48 6f 6f 6b } //1 SetKeyHook
		$a_01_16 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 72 64 61 6d 61 78 2e 63 6f 6d } //1 http://www.ardamax.com
		$a_01_17 = {41 72 64 61 6d 61 78 20 4b 65 79 6c 6f 67 67 65 72 } //1 Ardamax Keylogger
		$a_01_18 = {41 4b 4c 5f 54 45 53 54 } //1 AKL_TEST
		$a_01_19 = {2e 30 30 31 5f } //1 .001_
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1) >=18
 
}
rule MonitoringTool_Win32_Ardamax_17{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 20 00 00 "
		
	strings :
		$a_01_0 = {45 6e 67 69 6e 65 20 42 75 69 6c 64 65 72 } //1 Engine Builder
		$a_01_1 = {45 78 65 63 75 74 61 62 6c 65 20 6e 61 6d 65 20 69 73 20 72 65 71 75 69 72 65 64 2e } //2 Executable name is required.
		$a_01_2 = {57 68 65 6e 20 73 6f 6d 65 6f 6e 65 20 63 6c 69 63 6b 73 20 22 25 73 22 2c 20 } //2 When someone clicks "%s", 
		$a_01_3 = {77 69 6c 6c 20 62 65 20 69 6e 76 69 73 69 62 6c 79 20 69 6e 73 74 61 6c 6c 65 64 2e 20 } //2 will be invisibly installed. 
		$a_01_4 = {49 74 20 77 69 6c 6c 20 73 74 61 72 74 20 6c 61 75 6e 63 68 69 6e 67 20 } //2 It will start launching 
		$a_01_5 = {69 6e 76 69 73 69 62 6c 65 20 69 6e 20 74 68 65 20 73 79 73 74 65 6d 20 74 72 61 79 } //2 invisible in the system tray
		$a_01_6 = {45 61 63 68 20 25 69 20 25 73 20 69 74 20 77 69 6c 6c 20 73 65 6e 64 20 6c 6f 67 73 20 74 6f 20 22 25 73 22 20 76 69 61 20 65 2d 6d 61 69 6c 2e 20 } //3 Each %i %s it will send logs to "%s" via e-mail. 
		$a_01_7 = {45 61 63 68 20 25 69 20 25 73 20 69 74 20 77 69 6c 6c 20 75 70 6c 6f 61 64 20 6c 6f 67 73 20 74 6f 20 74 68 65 20 22 25 73 22 20 66 6f 6c 64 65 72 20 6f 6e 20 74 68 65 20 46 54 50 20 73 65 72 76 65 72 20 22 25 73 22 2e 20 } //3 Each %i %s it will upload logs to the "%s" folder on the FTP server "%s". 
		$a_01_8 = {54 6f 20 72 65 73 74 6f 72 65 20 56 69 73 69 62 6c 65 20 4d 6f 64 65 20 70 72 65 73 73 3a } //2 To restore Visible Mode press:
		$a_01_9 = {44 65 70 6c 6f 79 6d 65 6e 74 20 70 61 63 6b 61 67 65 20 63 72 65 61 74 65 64 20 73 75 63 63 65 73 } //2 Deployment package created succes
		$a_01_10 = {54 6f 20 65 6e 61 62 6c 65 2f 64 69 73 61 62 6c 65 20 74 68 65 20 69 6e 76 69 73 69 62 6c 65 20 6d 6f 64 65 2c 20 74 68 65 20 22 } //2 To enable/disable the invisible mode, the "
		$a_01_11 = {77 69 6c 6c 20 61 75 74 6f 6d 61 74 69 63 61 6c 6c 79 20 64 65 6c 65 74 65 20 69 74 73 65 6c 66 20 6f 6e 20 } //2 will automatically delete itself on 
		$a_01_12 = {45 61 63 68 20 74 69 6d 65 20 74 68 65 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 70 61 63 6b 61 67 65 20 69 73 20 6c 61 75 6e 63 68 65 64 2c 20 69 74 20 77 69 6c 6c 20 64 69 73 70 6c 61 79 20 74 68 65 20 72 65 6d 69 6e 64 65 72 20 74 68 61 74 20 79 6f 75 20 73 68 6f 75 6c 64 20 72 65 67 69 73 74 65 72 20 69 74 2e } //3 Each time the installation package is launched, it will display the reminder that you should register it.
		$a_01_13 = {54 68 65 20 22 4c 61 75 6e 63 68 20 61 74 20 57 69 6e 64 6f 77 73 20 73 74 61 72 74 75 70 22 20 6f 70 74 69 6f 6e 20 28 4f 70 74 69 6f 6e 73 20 50 61 67 65 29 20 69 73 20 64 69 73 61 62 6c 65 64 2e 20 54 68 65 20 } //3 The "Launch at Windows startup" option (Options Page) is disabled. The 
		$a_01_14 = {50 61 73 73 77 6f 72 64 20 70 72 6f 74 65 63 74 69 6f 6e 20 28 53 65 63 75 72 69 74 79 20 50 61 67 65 29 20 69 73 20 6e 6f 74 20 61 63 74 69 76 65 2e } //2 Password protection (Security Page) is not active.
		$a_01_15 = {59 6f 75 20 68 61 76 65 20 25 69 20 64 61 79 28 73 29 20 6c 65 66 74 } //3 You have %i day(s) left
		$a_01_16 = {55 57 4d 5f 57 4e 44 4d 4f 4e 48 4f 4f 4b 5f 4d 53 47 2d } //5 UWM_WNDMONHOOK_MSG-
		$a_01_17 = {55 57 4d 5f 4b 45 59 48 4f 4f 4b 5f 4d 53 47 2d } //5 UWM_KEYHOOK_MSG-
		$a_01_18 = {77 77 77 2e 61 72 64 61 6d 61 78 2e 63 6f 6d } //5 www.ardamax.com
		$a_01_19 = {41 72 64 61 6d 61 78 20 4b 65 79 6c 6f 67 67 65 72 } //4 Ardamax Keylogger
		$a_01_20 = {41 4b 4c 5f 54 45 53 54 2f 74 65 73 74 } //5 AKL_TEST/test
		$a_01_21 = {41 4b 4c 5f 54 45 53 54 } //3 AKL_TEST
		$a_01_22 = {43 61 6e 6e 6f 74 20 6c 61 75 6e 63 68 20 4c 6f 67 20 56 69 65 77 65 72 2e } //2 Cannot launch Log Viewer.
		$a_01_23 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 74 6f 20 63 6c 65 61 72 } //3 Are you sure to clear
		$a_01_24 = {49 6e 73 74 61 6e 74 2e 4c 6f 67 67 69 6e 67 45 6e 61 62 6c 65 64 } //4 Instant.LoggingEnabled
		$a_01_25 = {53 65 63 75 72 69 74 79 2e 50 72 6f 74 65 63 74 48 69 64 64 65 6e 4d 6f 64 65 } //2 Security.ProtectHiddenMode
		$a_01_26 = {49 6e 76 69 73 69 62 69 6c 69 74 79 2e 55 6e 69 6e 73 74 61 6c 6c 4c 69 73 } //2 Invisibility.UninstallLis
		$a_01_27 = {4f 70 74 69 6f 6e 73 2e 48 69 64 65 4f 6e 53 74 61 72 74 75 70 } //2 Options.HideOnStartup
		$a_01_28 = {4f 70 74 69 6f 6e 73 2e 48 69 64 65 48 6f 74 6b 65 79 } //2 Options.HideHotkey
		$a_01_29 = {74 65 73 74 20 46 54 50 20 64 65 6c 69 76 65 72 79 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 6c 65 74 65 64 20 73 75 63 63 65 73 66 75 6c 6c 79 2e } //3 test FTP delivery has been completed succesfully.
		$a_01_30 = {74 65 73 74 20 65 2d 6d 61 69 6c 20 64 65 6c 69 76 65 72 79 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 6c 65 74 65 64 20 73 75 63 63 65 73 66 75 6c 6c 79 2e } //3 test e-mail delivery has been completed succesfully.
		$a_01_31 = {2f 6f 72 64 65 72 5f 61 6b 6c 2e 68 74 6d 6c } //4 /order_akl.html
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2+(#a_01_12  & 1)*3+(#a_01_13  & 1)*3+(#a_01_14  & 1)*2+(#a_01_15  & 1)*3+(#a_01_16  & 1)*5+(#a_01_17  & 1)*5+(#a_01_18  & 1)*5+(#a_01_19  & 1)*4+(#a_01_20  & 1)*5+(#a_01_21  & 1)*3+(#a_01_22  & 1)*2+(#a_01_23  & 1)*3+(#a_01_24  & 1)*4+(#a_01_25  & 1)*2+(#a_01_26  & 1)*2+(#a_01_27  & 1)*2+(#a_01_28  & 1)*2+(#a_01_29  & 1)*3+(#a_01_30  & 1)*3+(#a_01_31  & 1)*4) >=28
 
}
rule MonitoringTool_Win32_Ardamax_18{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 00 72 00 64 00 61 00 6d 00 61 00 78 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //1 Ardamax Keylogger
		$a_01_1 = {41 00 4b 00 4c 00 4d 00 57 00 00 00 } //1
		$a_01_2 = {6d 00 73 00 6e 00 6d 00 73 00 67 00 72 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_01_3 = {00 22 20 61 6c 74 3d 22 22 2f 3e 3c 2f 70 3e 00 } //1 ∀愠瑬∽⼢㰾瀯>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule MonitoringTool_Win32_Ardamax_19{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 41 00 4b 00 56 00 2e 00 30 00 30 00 30 00 } //1 C:\AKV.000
		$a_01_1 = {41 00 72 00 64 00 61 00 6d 00 61 00 78 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //1 Ardamax Keylogger
		$a_01_2 = {25 00 62 00 5f 00 25 00 64 00 5f 00 25 00 59 00 5f 00 5f 00 25 00 48 00 5f 00 25 00 4d 00 5f 00 25 00 53 00 2e 00 6a 00 70 00 67 00 } //1 %b_%d_%Y__%H_%M_%S.jpg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule MonitoringTool_Win32_Ardamax_20{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 53 47 2d 39 36 38 43 33 30 34 33 2d 31 31 32 38 2d 34 33 64 63 2d 38 33 41 39 2d 35 35 31 32 32 43 38 44 38 37 43 31 } //4 MSG-968C3043-1128-43dc-83A9-55122C8D87C1
		$a_01_1 = {5c 41 6b 6c 5c 6b 68 5c 52 65 6c 65 61 73 65 5c 6b 68 2e 70 64 62 } //4 \Akl\kh\Release\kh.pdb
		$a_01_2 = {41 4b 4c 2e 30 30 36 } //2 AKL.006
		$a_01_3 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //1 GetKeyboardState
		$a_01_4 = {53 65 74 4b 65 79 48 6f 6f 6b } //1 SetKeyHook
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}
rule MonitoringTool_Win32_Ardamax_21{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {41 4b 4c 2e 30 30 37 00 48 6f 6f 6b 00 55 6e 68 6f 6f 6b } //4
		$a_01_1 = {41 4b 4c 2e 64 6c 6c 00 41 64 64 4d 6f 6e 69 74 6f 72 65 64 57 6e 64 } //2
		$a_01_2 = {50 72 6f 6a 65 63 74 73 5c 41 4b 4c 5c 6b 68 } //2 Projects\AKL\kh
		$a_01_3 = {53 65 74 4b 65 79 48 6f 6f 6b 00 } //1
		$a_01_4 = {53 65 74 57 6e 64 43 61 6c 6c 48 6f 6f 6b 00 } //1
		$a_01_5 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
		$a_01_6 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 00 } //1 湕潨歯楗摮睯䡳潯䕫x
		$a_01_7 = {49 6e 69 74 69 61 6c 69 7a 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e 00 } //1 湉瑩慩楬敺牃瑩捩污敓瑣潩n
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}
rule MonitoringTool_Win32_Ardamax_22{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 65 00 6e 00 67 00 69 00 6e 00 65 00 20 00 74 00 6f 00 20 00 66 00 69 00 6c 00 65 00 } //1 keylogger engine to file
		$a_01_1 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 4c 00 69 00 63 00 65 00 6e 00 73 00 65 00 20 00 57 00 61 00 72 00 6e 00 69 00 6e 00 67 00 } //1 Keylogger License Warning
		$a_01_2 = {48 00 69 00 64 00 64 00 65 00 6e 00 20 00 6d 00 6f 00 64 00 65 00 20 00 6f 00 6e 00 3a 00 } //1 Hidden mode on:
		$a_01_3 = {4b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 73 00 20 00 4c 00 6f 00 67 00 } //1 Keystrokes Log
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule MonitoringTool_Win32_Ardamax_23{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR,1a 00 1a 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 74 73 5c 41 4b 4c 5c 6b 68 5c 52 65 6c 65 61 73 65 5c 6b 68 2e 70 64 62 00 00 } //10
		$a_01_1 = {04 00 41 4b 4c 2e 64 6c 6c 00 41 64 64 4d 6f 6e 69 74 6f 72 65 64 57 6e 64 00 43 6c 65 61 72 4b 65 79 48 6f 6f 6b 00 } //10
		$a_01_2 = {35 00 37 00 38 00 43 00 45 00 36 00 33 00 45 00 31 00 30 00 35 00 31 00 34 00 34 00 43 00 37 00 42 00 39 00 41 00 36 00 31 00 38 00 44 00 42 00 31 00 43 00 41 00 38 00 33 00 46 00 43 00 34 00 } //3 578CE63E105144C7B9A618DB1CA83FC4
		$a_01_3 = {34 00 32 00 44 00 39 00 32 00 37 00 32 00 30 00 32 00 31 00 35 00 46 00 34 00 34 00 35 00 42 00 38 00 43 00 32 00 35 00 33 00 34 00 45 00 38 00 42 00 45 00 35 00 31 00 42 00 37 00 43 00 30 00 } //3 42D92720215F445B8C2534E8BE51B7C0
		$a_01_4 = {52 65 6d 6f 76 65 4d 6f 6e 69 74 6f 72 65 64 57 6e 64 } //1 RemoveMonitoredWnd
		$a_01_5 = {6b 65 79 62 64 5f 65 76 65 6e 74 } //1 keybd_event
		$a_01_6 = {4d 61 70 56 69 72 74 75 61 6c 4b 65 79 57 } //1 MapVirtualKeyW
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=26
 
}
rule MonitoringTool_Win32_Ardamax_24{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 00 4b 00 4c 00 4d 00 57 00 } //4 AKLMW
		$a_01_1 = {54 00 68 00 65 00 20 00 6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 77 00 69 00 6c 00 6c 00 20 00 61 00 75 00 74 00 6f 00 6d 00 61 00 74 00 69 00 63 00 61 00 6c 00 6c 00 79 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 69 00 74 00 73 00 65 00 6c 00 66 00 20 00 6f 00 6e 00 } //4 The keylogger will automatically delete itself on
		$a_01_2 = {41 4b 56 2e 65 78 65 00 2e 63 68 6d 00 } //4
		$a_01_3 = {4c 00 6f 00 63 00 61 00 6c 00 5c 00 7b 00 45 00 33 00 38 00 39 00 33 00 41 00 42 00 46 00 2d 00 35 00 33 00 45 00 30 00 2d 00 34 00 32 00 32 00 38 00 2d 00 39 00 41 00 32 00 37 00 2d 00 31 00 43 00 36 00 39 00 46 00 42 00 31 00 44 00 36 00 37 00 43 00 32 00 7d 00 } //1 Local\{E3893ABF-53E0-4228-9A27-1C69FB1D67C2}
		$a_01_4 = {4c 00 6f 00 63 00 61 00 6c 00 5c 00 7b 00 31 00 42 00 46 00 39 00 30 00 44 00 41 00 37 00 2d 00 42 00 34 00 32 00 34 00 2d 00 34 00 33 00 62 00 66 00 2d 00 41 00 45 00 42 00 41 00 2d 00 41 00 43 00 45 00 34 00 34 00 32 00 41 00 34 00 44 00 34 00 32 00 39 00 7d 00 } //1 Local\{1BF90DA7-B424-43bf-AEBA-ACE442A4D429}
		$a_01_5 = {4c 00 6f 00 63 00 61 00 6c 00 5c 00 7b 00 38 00 37 00 36 00 31 00 41 00 35 00 32 00 35 00 2d 00 38 00 38 00 39 00 31 00 2d 00 34 00 66 00 31 00 62 00 2d 00 38 00 35 00 41 00 46 00 2d 00 32 00 42 00 43 00 35 00 45 00 42 00 31 00 32 00 32 00 33 00 38 00 41 00 7d 00 } //1 Local\{8761A525-8891-4f1b-85AF-2BC5EB12238A}
		$a_01_6 = {4c 00 6f 00 63 00 61 00 6c 00 5c 00 7b 00 30 00 41 00 42 00 31 00 46 00 41 00 41 00 38 00 2d 00 37 00 42 00 31 00 31 00 2d 00 34 00 32 00 39 00 31 00 2d 00 42 00 43 00 43 00 44 00 2d 00 36 00 36 00 36 00 39 00 45 00 38 00 44 00 44 00 31 00 37 00 46 00 36 00 7d 00 } //1 Local\{0AB1FAA8-7B11-4291-BCCD-6669E8DD17F6}
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}
rule MonitoringTool_Win32_Ardamax_25{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR,16 00 16 00 16 00 00 "
		
	strings :
		$a_01_0 = {3c 2f 62 6f 64 79 3e 3c 2f 68 74 6d 6c 3e 00 00 4c 6f 61 64 69 6e 67 20 4b 65 79 73 74 72 6f 6b 65 73 20 4c 6f 67 2e 2e 2e } //10
		$a_01_1 = {22 25 73 22 20 4b 65 79 73 74 72 6f 6b 65 73 20 4c 6f 67 20 66 69 6c 65 20 63 61 6e 6e 6f 74 20 6f 70 65 6e 2e } //1 "%s" Keystrokes Log file cannot open.
		$a_01_2 = {22 25 73 22 20 4b 65 79 73 74 72 6f 6b 65 73 20 4c 6f 67 20 66 69 6c 65 20 63 6f 72 72 75 70 74 65 64 2e } //1 "%s" Keystrokes Log file corrupted.
		$a_01_3 = {55 6e 6b 6e 6f 77 6e 20 22 25 73 22 20 4b 65 79 73 74 72 6f 6b 65 73 20 4c 6f 67 20 66 69 6c 65 20 66 6f 72 6d 61 74 2e } //1 Unknown "%s" Keystrokes Log file format.
		$a_01_4 = {46 69 6c 74 65 72 69 6e 67 20 4b 65 79 73 74 72 6f 6b 65 73 20 4c 6f 67 2e 2e 2e } //1 Filtering Keystrokes Log...
		$a_01_5 = {53 74 6f 72 69 6e 67 20 4b 65 79 73 74 72 6f 6b 65 73 20 4c 6f 67 2e 2e 2e } //1 Storing Keystrokes Log...
		$a_01_6 = {53 65 61 72 63 68 69 6e 67 20 6c 6f 67 73 2e 2e 2e } //1 Searching logs...
		$a_01_7 = {4c 6f 67 73 20 6e 6f 74 20 66 6f 75 6e 64 2e } //1 Logs not found.
		$a_01_8 = {4c 6f 61 64 69 6e 67 20 53 63 72 65 65 6e 73 68 6f 74 73 2e 2e 2e } //1 Loading Screenshots...
		$a_01_9 = {22 25 73 22 20 53 63 72 65 65 6e 73 68 6f 74 73 20 66 69 6c 65 20 63 61 6e 6e 6f 74 20 6f 70 65 6e 2e } //1 "%s" Screenshots file cannot open.
		$a_01_10 = {22 25 73 22 20 53 63 72 65 65 6e 73 68 6f 74 73 20 66 69 6c 65 20 63 6f 72 72 75 70 74 65 64 2e } //1 "%s" Screenshots file corrupted.
		$a_01_11 = {55 6e 6b 6e 6f 77 6e 20 22 25 73 22 20 53 63 72 65 65 6e 73 68 6f 74 73 20 66 69 6c 65 20 66 6f 72 6d 61 74 2e } //1 Unknown "%s" Screenshots file format.
		$a_01_12 = {46 69 6c 74 65 72 69 6e 67 20 53 63 72 65 65 6e 73 68 6f 74 } //1 Filtering Screenshot
		$a_01_13 = {3c 61 20 68 72 65 66 3d 22 73 63 72 25 69 2e 6a 70 67 22 3e 3c 69 6d 67 20 73 72 63 3d 22 74 68 75 6d 62 25 69 2e 6a 70 67 22 20 62 6f 72 64 65 72 3d 22 30 22 20 2f 3e 3c 2f 61 3e } //1 <a href="scr%i.jpg"><img src="thumb%i.jpg" border="0" /></a>
		$a_01_14 = {53 74 6f 72 69 6e 67 20 53 63 72 65 65 6e 73 68 6f 74 73 2e 2e 2e } //1 Storing Screenshots...
		$a_01_15 = {25 73 5c 73 63 72 25 69 2e 6a 70 67 } //1 %s\scr%i.jpg
		$a_01_16 = {25 73 5c 74 68 75 6d 62 25 69 2e 6a 70 67 } //1 %s\thumb%i.jpg
		$a_01_17 = {4c 6f 61 64 69 6e 67 20 57 65 62 20 4c 6f 67 2e 2e 2e } //1 Loading Web Log...
		$a_01_18 = {22 25 73 22 20 57 65 62 20 4c 6f 67 20 66 69 6c 65 20 63 61 6e 6e 6f 74 20 6f 70 65 6e 2e } //1 "%s" Web Log file cannot open.
		$a_01_19 = {22 25 73 22 20 57 65 62 20 4c 6f 67 20 66 69 6c 65 20 63 6f 72 72 75 70 74 65 64 2e } //1 "%s" Web Log file corrupted.
		$a_01_20 = {55 6e 6b 6e 6f 77 6e 20 22 25 73 22 20 57 65 62 20 4c 6f 67 20 66 69 6c 65 20 66 6f 72 6d 61 74 2e } //1 Unknown "%s" Web Log file format.
		$a_01_21 = {46 69 6c 74 65 72 69 6e 67 20 57 65 62 20 4c 6f 67 2e 2e 2e } //1 Filtering Web Log...
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1) >=22
 
}