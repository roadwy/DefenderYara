
rule MonitoringTool_Win32_ActiveKeyLogger{
	meta:
		description = "MonitoringTool:Win32/ActiveKeyLogger,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 64 76 61 6e 63 65 64 20 49 6e 76 69 73 69 62 6c 65 20 4b 65 79 6c 6f 67 67 65 72 20 28 4b 65 79 73 74 72 6f 6b 65 73 20 54 79 70 65 64 29 } //1 Advanced Invisible Keylogger (Keystrokes Typed)
		$a_03_1 = {54 69 6d 65 3a [0-10] 57 69 6e 64 6f 77 20 54 69 74 6c 65 3a [0-10] 4b 65 79 73 74 72 6f 6b 65 73 3a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule MonitoringTool_Win32_ActiveKeyLogger_2{
	meta:
		description = "MonitoringTool:Win32/ActiveKeyLogger,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 53 4f 46 54 57 41 52 45 5c 57 69 6e 73 6f 75 6c 5c [0-02] 4b 65 79 6c 6f 67 67 65 72 } //10
		$a_01_1 = {2e 64 6c 6c 00 53 65 74 48 6f 6f 6b 00 } //2
		$a_03_2 = {41 63 74 69 76 65 20 4b 65 79 20 4c 6f 67 67 65 72 20 52 65 70 6f 72 74 [0-14] 2e 61 64 64 72 65 73 73 2e 63 6f 6d } //2
		$a_03_3 = {54 6f 74 61 6c 57 69 6e [0-10] 41 63 74 69 76 65 20 4b 65 79 20 4c 6f 67 67 65 72 3a 20 4b 65 79 73 74 72 6f 6b 65 73 } //2
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=12
 
}