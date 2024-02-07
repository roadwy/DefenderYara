
rule MonitoringTool_Win32_AdvancedKeylogger{
	meta:
		description = "MonitoringTool:Win32/AdvancedKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 32 43 32 45 46 35 46 2d 45 32 30 30 2d 34 31 37 65 2d 41 45 32 30 2d 42 31 42 32 34 31 45 36 42 45 33 39 } //01 00  A2C2EF5F-E200-417e-AE20-B1B241E6BE39
		$a_01_1 = {41 72 65 79 6f 75 53 75 72 65 44 65 6c 65 74 65 54 68 69 73 4c 6f 67 } //01 00  AreyouSureDeleteThisLog
		$a_01_2 = {53 63 72 65 65 6e 74 73 68 6f 74 50 61 67 65 43 6f 6c } //01 00  ScreentshotPageCol
		$a_01_3 = {2e 63 6f 6d 2f 78 70 61 64 76 61 6e 63 65 64 6b 65 79 6c 6f 67 67 65 72 2f } //00 00  .com/xpadvancedkeylogger/
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_AdvancedKeylogger_2{
	meta:
		description = "MonitoringTool:Win32/AdvancedKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 03 00 00 07 00 "
		
	strings :
		$a_01_0 = {41 64 76 61 6e 63 65 64 20 4b 65 79 6c 6f 67 67 65 72 20 69 73 20 77 61 74 63 68 69 6e 67 20 79 6f 75 } //07 00  Advanced Keylogger is watching you
		$a_01_1 = {50 72 65 70 61 72 69 6e 67 20 74 6f 20 73 65 6e 64 20 6c 6f 67 20 76 69 61 20 65 6d 61 69 6c 2e 2e 2e } //08 00  Preparing to send log via email...
		$a_01_2 = {50 52 4f 44 55 43 45 44 20 42 59 20 41 44 56 41 4e 43 45 44 20 4b 45 59 4c 4f 47 47 45 52 20 4c 4f 47 20 50 41 52 53 45 52 } //00 00  PRODUCED BY ADVANCED KEYLOGGER LOG PARSER
		$a_00_3 = {5d 04 00 00 af 42 00 00 } //5c 1d 
	condition:
		any of ($a_*)
 
}