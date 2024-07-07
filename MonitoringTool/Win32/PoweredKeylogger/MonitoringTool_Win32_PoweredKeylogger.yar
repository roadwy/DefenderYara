
rule MonitoringTool_Win32_PoweredKeylogger{
	meta:
		description = "MonitoringTool:Win32/PoweredKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 6f 77 65 72 65 64 20 6b 65 79 6c 6f 67 67 65 72 00 } //1
		$a_01_1 = {75 00 73 00 65 00 20 00 22 00 73 00 65 00 63 00 72 00 65 00 74 00 77 00 6f 00 72 00 64 00 22 00 20 00 } //1 use "secretword" 
		$a_01_2 = {74 00 65 00 73 00 74 00 20 00 65 00 2d 00 6d 00 61 00 69 00 6c 00 21 00 } //1 test e-mail!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}