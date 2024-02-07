
rule MonitoringTool_Win32_RefogKeylogger{
	meta:
		description = "MonitoringTool:Win32/RefogKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 70 6b 2e 64 6c 6c 00 } //01 00 
		$a_01_1 = {57 4d 5f 4b 45 59 48 4f 4f 4b 5f 4b 47 00 } //01 00  䵗䭟奅佈䭏䭟G
		$a_03_2 = {8b 44 24 04 68 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 50 e8 90 01 02 00 00 83 c4 18 b8 01 00 00 00 c2 04 00 90 00 } //01 00 
		$a_01_3 = {6a 00 56 50 6a 04 ff d7 8b 4c 24 14 6a 00 56 99 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_RefogKeylogger_2{
	meta:
		description = "MonitoringTool:Win32/RefogKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {77 00 77 00 77 00 2e 00 72 00 65 00 66 00 6f 00 67 00 2e 00 63 00 6f 00 6d 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2f 00 69 00 65 00 35 00 2e 00 7a 00 69 00 70 00 } //02 00  www.refog.com/files/ie5.zip
		$a_01_1 = {41 00 6c 00 6c 00 20 00 43 00 68 00 61 00 74 00 73 00 20 00 77 00 69 00 74 00 68 00 20 00 74 00 68 00 69 00 73 00 20 00 43 00 6f 00 6e 00 74 00 61 00 63 00 74 00 } //00 00  All Chats with this Contact
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_RefogKeylogger_3{
	meta:
		description = "MonitoringTool:Win32/RefogKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 02 00 "
		
	strings :
		$a_03_0 = {4d 70 6b 2e 64 6c 6c 00 46 90 02 02 46 90 02 02 46 90 00 } //02 00 
		$a_03_1 = {4d 70 6b 69 2e 64 6c 6c 00 46 90 02 02 46 90 02 02 46 90 00 } //02 00 
		$a_01_2 = {4d 50 4b 36 34 } //02 00  MPK64
		$a_01_3 = {53 00 3a 00 28 00 4d 00 4c 00 3b 00 3b 00 4e 00 57 00 3b 00 3b 00 3b 00 4c 00 57 00 29 00 } //01 00  S:(ML;;NW;;;LW)
		$a_01_4 = {57 4d 5f 4b 45 59 48 4f 4f 4b } //01 00  WM_KEYHOOK
		$a_01_5 = {57 4d 5f 4d 4f 55 53 45 48 4f 4f 4b } //01 00  WM_MOUSEHOOK
		$a_01_6 = {57 4d 5f 43 52 45 41 54 45 48 4f 4f 4b } //01 00  WM_CREATEHOOK
		$a_01_7 = {57 4d 5f 53 48 4f 57 48 4f 4f 4b } //01 00  WM_SHOWHOOK
		$a_01_8 = {57 4d 5f 4d 4f 55 53 45 4d 4f 56 45 48 4f 4f 4b } //01 00  WM_MOUSEMOVEHOOK
		$a_01_9 = {57 4d 5f 50 52 4f 47 52 55 4e 48 4f 4f 4b } //01 00  WM_PROGRUNHOOK
		$a_01_10 = {57 4d 5f 50 52 4f 47 53 54 4f 50 48 4f 4f 4b } //01 00  WM_PROGSTOPHOOK
		$a_01_11 = {57 4d 5f 47 45 54 57 4e 44 44 4c 4c } //00 00  WM_GETWNDDLL
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_RefogKeylogger_4{
	meta:
		description = "MonitoringTool:Win32/RefogKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 72 65 66 6f 67 2e 63 6f 6d 2f 75 6e 69 6e 73 } //01 00  www.refog.com/unins
		$a_01_1 = {6d 70 6b 76 69 65 77 2e 65 78 65 00 } //01 00 
		$a_01_2 = {52 45 46 4f 47 20 4d 6f 6e 69 74 6f 72 20 69 73 20 61 20 6d 75 6c 74 69 66 75 6e 63 74 69 6f 6e 61 6c 20 6b 65 79 62 6f 61 72 64 } //01 00  REFOG Monitor is a multifunctional keyboard
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 52 65 66 6f 67 20 53 6f 66 74 77 61 72 65 } //01 00  SOFTWARE\Refog Software
		$a_01_4 = {7b 63 6f 6d 6d 6f 6e 61 70 70 64 61 74 61 7d 5c 4d 50 4b } //01 00  {commonappdata}\MPK
		$a_01_5 = {50 6c 65 61 73 65 20 75 73 65 20 45 6d 70 6c 6f 79 65 65 20 4d 6f 6e 69 74 6f 72 20 6f 72 20 54 65 72 6d 69 6e 61 6c 20 4d 6f 6e 69 74 6f 72 20 76 65 72 73 69 6f 6e 2e } //01 00  Please use Employee Monitor or Terminal Monitor version.
		$a_01_6 = {4b 47 42 20 53 70 79 20 48 6f 6d 65 2e 6c 6e 6b } //01 00  KGB Spy Home.lnk
		$a_01_7 = {52 45 46 4f 47 20 4b 65 79 6c 6f 67 67 65 72 2e 6c 6e 6b } //00 00  REFOG Keylogger.lnk
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_RefogKeylogger_5{
	meta:
		description = "MonitoringTool:Win32/RefogKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 0b 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 72 65 66 6f 67 2e 63 6f 6d } //01 00  http://www.refog.com
		$a_01_1 = {4d 50 4b 41 44 4d 49 4e 50 53 57 00 } //01 00  偍䅋䵄义卐W
		$a_01_2 = {4d 50 4b 2e 64 6c 6c 00 } //01 00  偍⹋汤l
		$a_01_3 = {4d 50 4b 36 34 2e 64 6c 6c 00 } //01 00  偍㙋⸴汤l
		$a_01_4 = {4d 50 4b 56 69 65 77 2e 65 78 65 5f 4d 41 49 4e 00 } //01 00 
		$a_01_5 = {72 75 6e 72 65 66 6f 67 00 } //01 00 
		$a_01_6 = {2f 6b 65 79 6c 6f 67 67 65 72 2f 75 70 67 72 61 64 65 5f 74 6f 5f 73 70 79 2e 68 74 6d 6c 00 } //01 00 
		$a_01_7 = {2f 66 69 6c 65 73 2f 6b 65 79 73 70 65 63 74 70 72 6f 2e 65 78 65 00 } //01 00 
		$a_01_8 = {2f 75 70 64 61 74 65 73 2f 69 6e 74 65 67 72 69 74 79 2f } //01 00  /updates/integrity/
		$a_01_9 = {52 45 46 4f 47 20 46 72 65 65 20 4b 65 79 6c 6f 67 67 65 72 00 } //01 00 
		$a_01_10 = {4d 70 6b 4e 65 74 49 6e 73 74 61 6c 6c 2e 65 78 65 20 2d 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 69 6e 73 74 61 6c 6c 65 72 } //00 00  MpkNetInstall.exe - application installer
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_RefogKeylogger_6{
	meta:
		description = "MonitoringTool:Win32/RefogKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 00 45 00 46 00 4f 00 47 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 53 00 65 00 74 00 75 00 70 00 } //01 00  REFOG Keylogger Setup
		$a_00_1 = {54 00 68 00 69 00 73 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 77 00 61 00 73 00 20 00 62 00 75 00 69 00 6c 00 74 00 20 00 77 00 69 00 74 00 68 00 20 00 49 00 6e 00 6e 00 6f 00 20 00 53 00 65 00 74 00 75 00 70 00 2e 00 } //01 00  This installation was built with Inno Setup.
		$a_02_2 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 90 01 04 52 00 45 00 46 00 4f 00 47 00 90 00 } //01 00 
		$a_02_3 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 90 01 04 52 00 45 00 46 00 4f 00 47 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 90 00 } //01 00 
		$a_02_4 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 90 01 04 52 00 45 00 46 00 4f 00 47 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_RefogKeylogger_7{
	meta:
		description = "MonitoringTool:Win32/RefogKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {5a 00 3a 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 73 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 52 00 65 00 70 00 6f 00 73 00 69 00 74 00 6f 00 72 00 79 00 5c 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 5c 00 44 00 65 00 6c 00 70 00 68 00 69 00 } //01 00  Z:\Projects\ReleaseRepository\MonitorProject\Delphi
		$a_00_1 = {4d 00 50 00 4b 00 2e 00 64 00 6c 00 6c 00 } //01 00  MPK.dll
		$a_00_2 = {4d 00 50 00 4b 00 36 00 34 00 2e 00 64 00 6c 00 6c 00 } //01 00  MPK64.dll
		$a_00_3 = {4d 00 50 00 4b 00 56 00 69 00 65 00 77 00 2e 00 65 00 78 00 65 00 } //01 00  MPKView.exe
		$a_00_4 = {72 00 75 00 6e 00 72 00 65 00 66 00 6f 00 67 00 } //01 00  runrefog
		$a_00_5 = {77 00 77 00 77 00 2e 00 72 00 65 00 66 00 6f 00 67 00 2e 00 63 00 6f 00 6d 00 } //01 00  www.refog.com
		$a_01_6 = {52 00 45 00 46 00 4f 00 47 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 00 00 } //01 00 
		$a_01_7 = {6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 5f 00 75 00 70 00 64 00 61 00 74 00 65 00 5f 00 66 00 72 00 6f 00 6d 00 5f 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 } //01 00  keylogger_update_from_program
		$a_01_8 = {6c 00 6f 00 67 00 73 00 40 00 76 00 69 00 73 00 74 00 61 00 2d 00 6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 } //00 00  logs@vista-keylogger.com
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_RefogKeylogger_8{
	meta:
		description = "MonitoringTool:Win32/RefogKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 4d 00 20 00 43 00 68 00 61 00 74 00 20 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 00 00 } //01 00 
		$a_01_1 = {4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 5c 00 44 00 65 00 6c 00 70 00 68 00 69 00 5c 00 4d 00 65 00 73 00 73 00 61 00 6e 00 67 00 65 00 72 00 53 00 70 00 79 00 2e 00 70 00 61 00 73 00 00 00 } //01 00 
		$a_01_2 = {4d 00 50 00 4b 00 41 00 44 00 4d 00 49 00 4e 00 50 00 53 00 57 00 00 00 } //01 00 
		$a_01_3 = {52 00 45 00 46 00 4f 00 47 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 00 00 } //01 00 
		$a_01_4 = {72 00 65 00 66 00 6f 00 67 00 2e 00 63 00 6f 00 6d 00 2f 00 3f 00 75 00 74 00 6d 00 5f 00 73 00 6f 00 75 00 72 00 63 00 65 00 3d 00 } //01 00  refog.com/?utm_source=
		$a_01_5 = {70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 6c 00 2d 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 2f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 2e 00 68 00 74 00 6d 00 6c 00 3f 00 75 00 74 00 6d 00 5f 00 73 00 6f 00 75 00 72 00 63 00 65 00 3d 00 } //01 00  personal-monitor/upgrade.html?utm_source=
		$a_01_6 = {6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2f 00 66 00 61 00 71 00 2e 00 68 00 74 00 6d 00 6c 00 3f 00 75 00 74 00 6d 00 5f 00 73 00 6f 00 75 00 72 00 63 00 65 00 3d 00 } //01 00  keylogger/faq.html?utm_source=
		$a_01_7 = {44 00 6f 00 6e 00 27 00 74 00 20 00 67 00 6f 00 21 00 20 00 47 00 65 00 74 00 20 00 52 00 45 00 46 00 4f 00 47 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 46 00 52 00 45 00 45 00 21 00 00 00 } //01 00 
		$a_01_8 = {72 00 75 00 6e 00 72 00 65 00 66 00 6f 00 67 00 00 00 } //01 00 
		$a_01_9 = {5c 00 53 00 70 00 79 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 46 00 6f 00 72 00 6d 00 2e 00 70 00 61 00 73 00 00 00 } //01 00 
		$a_01_10 = {4d 00 55 00 54 00 45 00 58 00 5f 00 50 00 52 00 4f 00 47 00 52 00 41 00 4d 00 5f 00 52 00 55 00 4e 00 4e 00 49 00 4e 00 47 00 3a 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_RefogKeylogger_9{
	meta:
		description = "MonitoringTool:Win32/RefogKeylogger,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {4b 00 47 00 42 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //01 00  KGB Keylogger
		$a_01_2 = {41 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 20 00 6b 00 65 00 79 00 20 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //01 00  Advanced key logger
		$a_01_3 = {4d 41 49 4c 20 46 52 4f 4d 3a 20 } //01 00  MAIL FROM: 
		$a_01_4 = {52 43 50 54 20 54 4f 3a } //01 00  RCPT TO:
		$a_01_5 = {47 65 74 4b 65 79 62 6f 61 72 64 54 79 70 65 } //01 00  GetKeyboardType
		$a_01_6 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //01 00  OpenClipboard
		$a_01_7 = {43 6c 6f 73 65 43 6c 69 70 62 6f 61 72 64 } //00 00  CloseClipboard
	condition:
		any of ($a_*)
 
}