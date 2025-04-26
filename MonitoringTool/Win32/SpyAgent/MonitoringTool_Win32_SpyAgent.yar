
rule MonitoringTool_Win32_SpyAgent{
	meta:
		description = "MonitoringTool:Win32/SpyAgent,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 70 79 41 67 65 6e 74 5f 48 57 4e 44 33 32 } //1 SpyAgent_HWND32
		$a_01_1 = {25 73 5c 73 61 6f 70 74 73 2e 64 61 74 } //1 %s\saopts.dat
		$a_01_2 = {53 70 79 74 65 63 68 20 53 70 79 41 67 65 6e 74 } //1 Spytech SpyAgent
		$a_01_3 = {43 6c 69 65 6e 74 20 68 6f 6f 6b 20 } //1 Client hook 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule MonitoringTool_Win32_SpyAgent_2{
	meta:
		description = "MonitoringTool:Win32/SpyAgent,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 77 69 6e 64 6f 77 73 5c 6c 73 61 73 73 2e 65 78 65 } //2 \windows\lsass.exe
		$a_01_1 = {53 50 59 41 47 45 4e 54 40 } //2 SPYAGENT@
		$a_01_2 = {3d 3e 4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 } //1 =>Keylogger Start
		$a_01_3 = {56 69 63 74 69 6d 20 69 73 20 4f 6e 6c 69 6e 65 } //1 Victim is Online
		$a_01_4 = {20 55 52 4c 20 48 49 53 54 4f 52 59 20 3d } //1  URL HISTORY =
		$a_01_5 = {4c 6f 67 20 53 74 61 72 74 20 20 } //1 Log Start  
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}