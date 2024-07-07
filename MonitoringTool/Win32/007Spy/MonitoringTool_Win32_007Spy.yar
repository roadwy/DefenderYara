
rule MonitoringTool_Win32_007Spy{
	meta:
		description = "MonitoringTool:Win32/007Spy,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 65 2d 73 70 79 2d 73 6f 66 74 77 61 72 65 2e 63 6f 6d } //1 www.e-spy-software.com
		$a_00_1 = {77 00 77 00 77 00 2e 00 65 00 2d 00 73 00 70 00 79 00 2d 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 2e 00 63 00 6f 00 6d 00 } //1 www.e-spy-software.com
		$a_01_2 = {54 69 6d 65 72 5f 4b 69 6c 6c 41 64 61 77 61 72 65 } //10 Timer_KillAdaware
		$a_01_3 = {43 68 65 63 6b 20 74 68 69 73 20 74 6f 20 6d 61 6b 65 20 30 30 37 20 53 70 79 } //10 Check this to make 007 Spy
		$a_01_4 = {54 69 6d 65 72 5f 4b 65 79 6c 6f 67 67 65 72 } //10 Timer_Keylogger
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=13
 
}
rule MonitoringTool_Win32_007Spy_2{
	meta:
		description = "MonitoringTool:Win32/007Spy,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 08 00 00 "
		
	strings :
		$a_02_0 = {44 00 3a 00 5c 00 44 00 65 00 76 00 65 00 6c 00 6f 00 70 00 5c 00 6d 00 79 90 02 02 00 77 00 6f 00 72 00 6b 90 02 05 5c 00 30 00 30 00 37 00 53 00 70 00 79 00 33 90 00 } //10
		$a_00_1 = {4d 6f 6e 69 74 6f 72 69 6e 67 20 65 6e 67 69 6e 65 } //1 Monitoring engine
		$a_00_2 = {54 69 6d 65 72 5f 4b 65 79 6c 6f 67 67 65 72 } //1 Timer_Keylogger
		$a_00_3 = {53 70 79 30 30 37 2e 4d 79 58 50 42 75 74 74 6f 6e } //1 Spy007.MyXPButton
		$a_00_4 = {66 72 6d 4d 61 69 6e 00 0d 01 10 00 30 30 37 20 53 70 79 20 53 6f 66 74 77 61 72 65 } //1
		$a_00_5 = {6b 65 79 62 64 5f 6c 6f 67 33 32 31 5f 4b 65 79 50 72 65 73 73 65 64 } //1 keybd_log321_KeyPressed
		$a_00_6 = {77 00 77 00 77 00 2e 00 65 00 2d 00 73 00 70 00 79 00 2d 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 2e 00 63 00 6f 00 6d 00 } //1 www.e-spy-software.com
		$a_00_7 = {73 76 63 68 6f 73 74 00 73 76 63 68 6f 73 74 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=10
 
}