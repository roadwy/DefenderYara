
rule MonitoringTool_Win32_SpyKeylogger{
	meta:
		description = "MonitoringTool:Win32/SpyKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,17 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {6b 6c 2e 64 6c 6c 90 02 04 6b 6c 49 6e 69 74 69 61 6c 69 7a 65 64 90 00 } //10
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //10 Software\Borland\Delphi\Locales
		$a_00_2 = {4b 00 65 00 79 00 20 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 64 00 69 00 6e 00 61 00 6d 00 69 00 63 00 20 00 6c 00 69 00 6e 00 6b 00 20 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 } //1 Key logger dinamic link library
		$a_00_3 = {4b 00 65 00 79 00 4c 00 6f 00 67 00 67 00 65 00 72 00 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 } //1 KeyLoggerMessage
		$a_00_4 = {4b 65 79 4c 6f 67 67 65 72 53 68 61 72 65 64 4d 65 6d } //1 KeyLoggerSharedMem
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=22
 
}