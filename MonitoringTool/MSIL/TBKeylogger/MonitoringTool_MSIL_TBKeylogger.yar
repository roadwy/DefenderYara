
rule MonitoringTool_MSIL_TBKeylogger{
	meta:
		description = "MonitoringTool:MSIL/TBKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 79 6c 6f 67 67 65 72 5f 54 68 65 42 65 73 74 4b 65 79 6c 6f 67 67 65 72 } //01 00  Keylogger_TheBestKeylogger
		$a_01_1 = {45 6e 61 62 6c 65 4b 65 79 73 74 72 6f 6b 65 4c 6f 67 67 69 6e 67 } //01 00  EnableKeystrokeLogging
		$a_01_2 = {54 61 6b 65 53 63 72 65 65 6e 73 68 6f 74 6f 6e 4d 6f 75 73 65 43 6c 69 63 6b } //01 00  TakeScreenshotonMouseClick
		$a_01_3 = {45 6d 61 69 6c 53 65 6e 64 4b 65 79 73 74 72 6f 6b 65 } //01 00  EmailSendKeystroke
		$a_01_4 = {46 54 50 53 65 6e 64 53 63 72 65 65 6e 73 68 6f 74 } //01 00  FTPSendScreenshot
		$a_01_5 = {55 73 62 53 65 6e 64 46 69 6c 65 77 61 74 63 68 65 72 } //00 00  UsbSendFilewatcher
		$a_00_6 = {78 7d 01 00 } //06 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_MSIL_TBKeylogger_2{
	meta:
		description = "MonitoringTool:MSIL/TBKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 5f 00 54 00 68 00 65 00 42 00 65 00 73 00 74 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //01 00  Keylogger_TheBestKeylogger
		$a_01_1 = {54 00 68 00 69 00 73 00 20 00 69 00 73 00 20 00 69 00 6e 00 76 00 69 00 73 00 69 00 62 00 6c 00 65 00 20 00 66 00 6f 00 72 00 6d 00 2e 00 } //01 00  This is invisible form.
		$a_01_2 = {54 00 68 00 69 00 73 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 69 00 73 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 6c 00 79 00 20 00 62 00 65 00 69 00 6e 00 67 00 20 00 6c 00 6f 00 67 00 67 00 65 00 64 00 20 00 62 00 79 00 20 00 54 00 68 00 65 00 20 00 42 00 65 00 73 00 74 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 } //01 00  This computer is currently being logged by The Best Keylogger.
		$a_01_3 = {54 00 61 00 6b 00 65 00 20 00 73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 20 00 77 00 68 00 65 00 6e 00 20 00 76 00 69 00 73 00 69 00 74 00 69 00 6e 00 67 00 20 00 61 00 20 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 } //01 00  Take screenshot when visiting a website
		$a_01_4 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2d 00 53 00 79 00 73 00 44 00 69 00 72 00 } //01 00  Keylogger-SysDir
		$a_01_5 = {4d 69 63 72 6f 73 6f 66 74 20 32 30 31 31 } //00 00  Microsoft 2011
		$a_00_6 = {5d 04 00 00 } //e0 20 
	condition:
		any of ($a_*)
 
}