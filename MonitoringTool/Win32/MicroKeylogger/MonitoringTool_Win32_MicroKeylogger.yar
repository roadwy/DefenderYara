
rule MonitoringTool_Win32_MicroKeylogger{
	meta:
		description = "MonitoringTool:Win32/MicroKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 00 69 00 63 00 72 00 6f 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //1 MicroKeylogger
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 53 00 79 00 73 00 4c 00 6f 00 67 00 67 00 65 00 72 00 } //1 SOFTWARE\Microsoft\SysLogger
		$a_01_2 = {3c 00 73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 66 00 69 00 6c 00 65 00 3e 00 } //1 <screenshotfile>
		$a_01_3 = {3c 00 2f 00 6b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 3e 00 } //1 </keystroke>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}