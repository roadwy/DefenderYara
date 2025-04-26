
rule MonitoringTool_Win32_PaqtoolKeylogger{
	meta:
		description = "MonitoringTool:Win32/PaqtoolKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {44 6f 20 79 6f 75 20 72 65 61 6c 6c 79 20 77 61 6e 74 20 74 6f 20 63 6c 6f 73 65 20 50 61 71 20 4b 65 79 4c 6f 67 } //1 Do you really want to close Paq KeyLog
		$a_02_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 70 61 71 74 6f 6f 6c 2e 63 6f 6d 2f 70 72 6f 64 75 63 74 2f 6b 65 79 6c 6f 67 2f 6b 65 79 6c 6f 67 5f ?? ?? ?? 2e 68 74 6d } //1
		$a_02_2 = {59 6f 75 20 68 61 76 65 20 61 6c 72 65 61 64 79 20 73 74 61 72 74 65 64 20 4b 65 79 6c 6f 67 2e ?? ?? ?? ?? 6f 6e 65 49 6e 73 74 61 6e 63 65 4d 75 74 65 78 74 50 61 71 4b 65 79 4c 6f 67 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*3) >=5
 
}