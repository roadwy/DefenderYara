
rule MonitoringTool_Win32_Winspy{
	meta:
		description = "MonitoringTool:Win32/Winspy,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 2d 53 70 79 20 53 6f 66 74 77 61 72 65 } //5 Win-Spy Software
		$a_01_1 = {57 69 6e 2d 53 70 79 20 4c 6f 67 69 6e 20 61 6e 64 20 50 61 73 73 77 6f 72 64 } //5 Win-Spy Login and Password
		$a_01_2 = {77 77 77 2e 77 69 6e 2d 73 70 79 2e 63 6f 6d } //5 www.win-spy.com
		$a_01_3 = {42 43 20 43 4f 4d 50 55 54 49 4e 47 } //3 BC COMPUTING
		$a_00_4 = {4b 65 79 6c 6f 67 } //2 Keylog
		$a_01_5 = {4b 65 79 53 74 61 74 65 } //2 KeyState
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_00_4  & 1)*2+(#a_01_5  & 1)*2) >=15
 
}
rule MonitoringTool_Win32_Winspy_2{
	meta:
		description = "MonitoringTool:Win32/Winspy,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_01_0 = {7b 00 4e 00 75 00 6d 00 4c 00 6f 00 63 00 6b 00 7d 00 } //2 {NumLock}
		$a_01_1 = {74 78 74 53 74 72 6f 6b 65 } //2 txtStroke
		$a_01_2 = {53 74 6f 70 4b 65 79 6c 6f 67 } //2 StopKeylog
		$a_01_3 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 GetAsyncKeyState
		$a_01_4 = {74 78 74 4b 65 79 4e } //2 txtKeyN
		$a_01_5 = {44 00 61 00 74 00 65 00 20 00 46 00 69 00 6c 00 65 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 64 00 3a 00 20 00 } //2 Date File Created: 
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=11
 
}
rule MonitoringTool_Win32_Winspy_3{
	meta:
		description = "MonitoringTool:Win32/Winspy,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 76 00 35 00 38 00 5c 00 57 00 69 00 6e 00 } //4 \Desktop\v58\Win
		$a_00_1 = {56 00 69 00 65 00 77 00 20 00 41 00 74 00 74 00 61 00 63 00 68 00 65 00 64 00 20 00 4c 00 6f 00 67 00 20 00 46 00 69 00 6c 00 65 00 } //2 View Attached Log File
		$a_00_2 = {36 00 39 00 2e 00 34 00 36 00 2e 00 31 00 38 00 2e 00 34 00 39 00 } //2 69.46.18.49
		$a_01_3 = {4b 65 79 4c 6f 67 } //2 KeyLog
		$a_00_4 = {77 00 69 00 6e 00 2d 00 73 00 70 00 79 00 } //2 win-spy
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*2+(#a_00_4  & 1)*2) >=8
 
}
rule MonitoringTool_Win32_Winspy_4{
	meta:
		description = "MonitoringTool:Win32/Winspy,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 76 00 35 00 38 00 5c 00 57 00 69 00 6e 00 } //4 \Desktop\v58\Win
		$a_01_1 = {52 65 6d 6f 74 65 20 48 6f 73 74 20 3a } //1 Remote Host :
		$a_01_2 = {2f 57 69 6e 2d 53 70 79 2e 63 6f 6d } //4 /Win-Spy.com
		$a_00_3 = {5c 00 64 00 6c 00 6c 00 33 00 32 00 5c 00 63 00 73 00 72 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //2 \dll32\csrss.exe
		$a_00_4 = {5c 00 64 00 6c 00 6c 00 33 00 32 00 5c 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //2 \dll32\services.exe
	condition:
		((#a_00_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*4+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=8
 
}
rule MonitoringTool_Win32_Winspy_5{
	meta:
		description = "MonitoringTool:Win32/Winspy,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 76 00 35 00 38 00 5c 00 57 00 69 00 6e 00 } //4 \Desktop\v58\Win
		$a_00_1 = {57 69 6e 2d 53 70 79 20 53 6f 66 74 77 61 72 65 } //4 Win-Spy Software
		$a_01_2 = {57 69 6e 2d 53 70 79 } //4 Win-Spy
		$a_00_3 = {53 74 65 61 6c 74 68 } //1 Stealth
		$a_00_4 = {57 00 69 00 6e 00 2d 00 53 00 70 00 79 00 20 00 4d 00 61 00 6e 00 75 00 61 00 6c 00 2e 00 64 00 6f 00 63 00 } //4 Win-Spy Manual.doc
		$a_01_5 = {4d 6f 6e 69 74 6f 72 46 69 72 65 46 6f 78 } //1 MonitorFireFox
		$a_01_6 = {73 74 61 72 74 20 57 69 6e 2d 53 70 79 } //4 start Win-Spy
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*4+(#a_01_2  & 1)*4+(#a_00_3  & 1)*1+(#a_00_4  & 1)*4+(#a_01_5  & 1)*1+(#a_01_6  & 1)*4) >=12
 
}
rule MonitoringTool_Win32_Winspy_6{
	meta:
		description = "MonitoringTool:Win32/Winspy,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 68 6b 49 6e 63 6c 75 64 65 4b 65 79 6c 6f 67 } //3 chkIncludeKeylog
		$a_01_1 = {43 00 6f 00 6e 00 74 00 61 00 63 00 74 00 20 00 61 00 64 00 6d 00 69 00 6e 00 40 00 77 00 69 00 6e 00 2d 00 73 00 70 00 79 00 2e 00 63 00 6f 00 6d 00 20 00 74 00 6f 00 20 00 70 00 75 00 72 00 63 00 68 00 61 00 73 00 65 00 20 00 61 00 64 00 64 00 69 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 20 00 6c 00 69 00 63 00 65 00 6e 00 73 00 65 00 2e 00 } //5 Contact admin@win-spy.com to purchase additional license.
		$a_01_2 = {52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 55 00 73 00 65 00 72 00 28 00 6c 00 6f 00 67 00 67 00 65 00 64 00 20 00 6f 00 6e 00 29 00 20 00 77 00 69 00 6c 00 6c 00 20 00 62 00 65 00 20 00 70 00 72 00 6f 00 6d 00 70 00 74 00 65 00 64 00 2e 00 20 00 44 00 6f 00 20 00 79 00 6f 00 75 00 20 00 77 00 61 00 6e 00 74 00 20 00 74 00 6f 00 20 00 63 00 6f 00 6e 00 74 00 69 00 6e 00 75 00 65 00 3f 00 } //3 Remote User(logged on) will be prompted. Do you want to continue?
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3) >=11
 
}
rule MonitoringTool_Win32_Winspy_7{
	meta:
		description = "MonitoringTool:Win32/Winspy,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 76 00 35 00 38 00 5c 00 57 00 69 00 6e 00 } //4 \Desktop\v58\Win
		$a_01_1 = {53 74 65 61 6c 74 68 } //1 Stealth
		$a_01_2 = {47 65 74 4d 53 4e 43 68 61 74 } //1 GetMSNChat
		$a_01_3 = {47 65 74 59 61 68 6f 6f 43 68 61 74 } //1 GetYahooChat
		$a_01_4 = {47 65 74 41 49 4d 43 68 61 74 } //1 GetAIMChat
		$a_01_5 = {47 65 74 49 43 51 43 68 61 74 } //1 GetICQChat
		$a_01_6 = {47 65 74 53 6b 79 70 65 43 68 61 74 } //1 GetSkypeChat
		$a_01_7 = {4c 6f 67 20 66 69 6c 65 20 6c 6f 63 61 74 69 6f 6e 3a } //1 Log file location:
		$a_01_8 = {43 68 61 74 20 4c 6f 67 67 65 72 } //1 Chat Logger
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=10
 
}
rule MonitoringTool_Win32_Winspy_8{
	meta:
		description = "MonitoringTool:Win32/Winspy,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 76 00 35 00 38 00 5c 00 57 00 69 00 6e 00 } //4 \Desktop\v58\Win
		$a_01_1 = {54 69 6d 65 72 53 63 72 65 65 6e 43 61 70 74 75 72 65 } //1 TimerScreenCapture
		$a_01_2 = {57 00 69 00 6e 00 2d 00 53 00 70 00 79 00 20 00 53 00 68 00 61 00 72 00 65 00 77 00 61 00 72 00 65 00 2e 00 } //4 Win-Spy Shareware.
		$a_01_3 = {3a 00 2a 00 3a 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00 3a 00 4f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00 2e 00 65 00 78 00 65 00 } //1 :*:Enabled:Outlook.exe
		$a_01_4 = {49 00 63 00 6f 00 6e 00 20 00 77 00 69 00 6c 00 6c 00 20 00 6e 00 6f 00 74 00 20 00 61 00 70 00 70 00 65 00 61 00 72 00 20 00 6f 00 6e 00 20 00 52 00 65 00 74 00 61 00 69 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 } //2 Icon will not appear on Retail version
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*4+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=10
 
}