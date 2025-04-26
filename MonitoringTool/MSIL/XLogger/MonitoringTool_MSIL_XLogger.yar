
rule MonitoringTool_MSIL_XLogger{
	meta:
		description = "MonitoringTool:MSIL/XLogger,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {58 4c 6f 67 67 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //1 XLogger.Properties
		$a_01_1 = {45 4e 41 42 4c 45 5f 4b 45 59 4c 4f 47 47 45 52 } //1 ENABLE_KEYLOGGER
		$a_01_2 = {45 4e 41 42 4c 45 5f 53 43 52 45 45 4e 53 48 4f 54 } //1 ENABLE_SCREENSHOT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}