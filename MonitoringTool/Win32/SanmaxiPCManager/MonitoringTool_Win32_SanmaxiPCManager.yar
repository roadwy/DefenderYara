
rule MonitoringTool_Win32_SanmaxiPCManager{
	meta:
		description = "MonitoringTool:Win32/SanmaxiPCManager,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 61 6e 6d 61 78 69 20 50 43 20 4d 61 6e 61 67 65 72 20 2d 20 54 65 78 74 20 4c 6f 67 20 52 65 70 6f 72 74 } //01 00  Sanmaxi PC Manager - Text Log Report
		$a_01_1 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 64 65 6c 65 74 65 20 61 6c 6c 20 63 61 70 74 75 72 65 64 20 55 53 42 2f 73 79 73 74 65 6d 20 6c 6f 67 73 20 70 65 72 6d 61 6e 65 6e 74 6c 79 2e } //01 00  Are you sure you want to delete all captured USB/system logs permanently.
		$a_01_2 = {53 63 72 65 65 6e 73 68 6f 74 20 72 65 70 6f 72 74 2e } //00 00  Screenshot report.
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_SanmaxiPCManager_2{
	meta:
		description = "MonitoringTool:Win32/SanmaxiPCManager,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 53 00 61 00 6e 00 6d 00 61 00 78 00 69 00 5c 00 4b 00 4c 00 6f 00 67 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 } //01 00  Software\Sanmaxi\KLog\Security
		$a_01_1 = {53 61 6e 6d 61 78 69 20 50 43 20 4d 61 6e 61 67 65 72 20 69 73 20 73 74 69 6c 6c 20 72 65 63 6f 72 64 69 6e 67 20 6b 65 79 20 73 74 72 6f 6b 65 73 } //01 00  Sanmaxi PC Manager is still recording key strokes
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6b 65 79 2d 6c 6f 67 67 65 72 2e 77 73 } //00 00  http://www.key-logger.ws
	condition:
		any of ($a_*)
 
}