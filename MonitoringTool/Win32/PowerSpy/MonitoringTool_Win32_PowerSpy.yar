
rule MonitoringTool_Win32_PowerSpy{
	meta:
		description = "MonitoringTool:Win32/PowerSpy,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {5c 00 65 00 6d 00 78 00 66 00 69 00 6c 00 65 00 2e 00 65 00 6d 00 78 00 [0-20] 69 00 6e 00 69 00 2e 00 69 00 6e 00 69 00 } //1
		$a_03_1 = {6a 65 8d 45 ?? 50 ff d6 6a 6d 8d ?? ?? ?? ?? ?? 51 ff d6 6a 78 8d ?? ?? ?? ?? ?? 52 ff d6 6a 70 8d ?? ?? ?? ?? ?? 50 ff d6 6a 73 8d ?? ?? ?? ?? ?? 51 ff d6 6a 74 8d ?? ?? ?? ?? ?? 52 ff d6 6a 6d 8d ?? ?? ?? ?? ?? 50 ff d6 6a 70 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule MonitoringTool_Win32_PowerSpy_2{
	meta:
		description = "MonitoringTool:Win32/PowerSpy,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {42 00 75 00 79 00 20 00 69 00 74 00 20 00 4f 00 6e 00 6c 00 69 00 6e 00 65 00 3a 00 20 00 77 00 77 00 77 00 2e 00 65 00 6d 00 61 00 74 00 72 00 69 00 78 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 62 00 75 00 79 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 Buy it Online: www.ematrixsoft.com/buy.html
		$a_02_1 = {61 00 70 00 70 00 69 00 6e 00 69 00 2e 00 69 00 6e 00 69 00 [0-20] 75 00 73 00 72 00 2e 00 69 00 6e 00 69 00 [0-20] 5c 00 65 00 6d 00 78 00 66 00 69 00 6c 00 65 00 } //1
		$a_02_2 = {63 00 6c 00 64 00 72 00 44 00 61 00 74 00 65 00 3d 00 23 00 [0-20] 5c 00 65 00 6d 00 78 00 70 00 73 00 74 00 6d 00 70 00 66 00 69 00 6c 00 65 00 2e 00 65 00 6d 00 78 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule MonitoringTool_Win32_PowerSpy_3{
	meta:
		description = "MonitoringTool:Win32/PowerSpy,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 00 65 00 6c 00 65 00 74 00 65 00 20 00 2a 00 20 00 46 00 72 00 6f 00 6d 00 20 00 4b 00 65 00 79 00 53 00 74 00 72 00 6f 00 6b 00 65 00 73 00 } //2 Delete * From KeyStrokes
		$a_01_1 = {44 00 6f 00 20 00 79 00 6f 00 75 00 20 00 77 00 61 00 6e 00 74 00 20 00 74 00 6f 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 61 00 6c 00 6c 00 20 00 6c 00 6f 00 67 00 73 00 20 00 62 00 65 00 66 00 6f 00 72 00 65 00 20 00 75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 69 00 6e 00 67 00 20 00 74 00 68 00 65 00 20 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 3f 00 } //2 Do you want to delete all logs before uninstalling the software?
		$a_01_2 = {74 00 68 00 65 00 20 00 27 00 53 00 65 00 6e 00 64 00 20 00 6c 00 6f 00 67 00 73 00 20 00 74 00 6f 00 20 00 79 00 6f 00 75 00 72 00 20 00 65 00 6d 00 61 00 69 00 6c 00 62 00 6f 00 78 00 27 00 20 00 63 00 68 00 65 00 63 00 6b 00 62 00 6f 00 78 00 20 00 61 00 6e 00 64 00 20 00 72 00 65 00 74 00 72 00 79 00 20 00 69 00 74 00 20 00 61 00 66 00 74 00 65 00 72 00 } //3 the 'Send logs to your emailbox' checkbox and retry it after
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=7
 
}
rule MonitoringTool_Win32_PowerSpy_4{
	meta:
		description = "MonitoringTool:Win32/PowerSpy,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 00 74 00 20 00 6f 00 6e 00 6c 00 79 00 20 00 64 00 65 00 6d 00 6f 00 6e 00 73 00 74 00 72 00 61 00 74 00 65 00 73 00 20 00 68 00 6f 00 77 00 20 00 74 00 68 00 65 00 20 00 65 00 6d 00 61 00 69 00 6c 00 20 00 66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 20 00 77 00 6f 00 72 00 6b 00 73 00 2e 00 20 00 41 00 66 00 74 00 65 00 72 00 20 00 79 00 6f 00 75 00 20 00 62 00 75 00 79 00 20 00 61 00 6e 00 64 00 20 00 75 00 6e 00 6c 00 6f 00 63 00 6b 00 } //3 It only demonstrates how the email function works. After you buy and unlock
		$a_01_1 = {4e 00 4f 00 54 00 45 00 3a 00 20 00 44 00 75 00 65 00 20 00 74 00 6f 00 20 00 74 00 68 00 65 00 20 00 6c 00 69 00 6d 00 69 00 74 00 61 00 74 00 69 00 6f 00 6e 00 20 00 6f 00 66 00 20 00 75 00 6e 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 2c 00 20 00 74 00 68 00 65 00 20 00 66 00 69 00 6c 00 65 00 20 00 61 00 74 00 74 00 61 00 63 00 68 00 65 00 64 00 20 00 69 00 73 00 20 00 61 00 } //3 NOTE: Due to the limitation of unregistered version, the file attached is a
		$a_01_2 = {53 65 6e 64 69 6e 67 20 52 65 70 6f 72 74 2e 2e 2e } //1 Sending Report...
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=7
 
}
rule MonitoringTool_Win32_PowerSpy_5{
	meta:
		description = "MonitoringTool:Win32/PowerSpy,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7b 00 53 00 63 00 72 00 6f 00 6c 00 6c 00 20 00 4c 00 6f 00 63 00 6b 00 7d 00 } //1 {Scroll Lock}
		$a_01_1 = {49 00 6e 00 73 00 65 00 72 00 74 00 20 00 49 00 6e 00 74 00 6f 00 20 00 57 00 69 00 6e 00 43 00 61 00 70 00 73 00 20 00 28 00 55 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 2c 00 20 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 29 00 20 00 56 00 61 00 6c 00 75 00 65 00 73 00 28 00 27 00 } //1 Insert Into WinCaps (Username, Content) Values('
		$a_01_2 = {65 4d 61 74 72 69 78 53 6f 66 74 20 50 6f 77 65 72 20 53 70 79 } //1 eMatrixSoft Power Spy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}