
rule MonitoringTool_Win32_SpyLanternKeylogger{
	meta:
		description = "MonitoringTool:Win32/SpyLanternKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {4c 6f 67 20 46 69 6c 65 73 20 28 2a 2e 6c 74 72 29 } //02 00  Log Files (*.ltr)
		$a_01_1 = {69 00 73 00 5f 00 6c 00 6f 00 63 00 61 00 6c 00 73 00 70 00 79 00 } //02 00  is_localspy
		$a_01_2 = {53 70 79 64 65 78 2c 20 49 6e 63 2e } //02 00  Spydex, Inc.
		$a_01_3 = {72 65 70 6f 72 74 5f 6b 65 79 5f 62 6f 74 74 6f 6d 2e 74 65 6d 70 6c } //00 00  report_key_bottom.templ
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_SpyLanternKeylogger_2{
	meta:
		description = "MonitoringTool:Win32/SpyLanternKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 6b 33 34 35 33 34 32 33 34 4d 45 44 52 45 57 73 64 66 77 65 4c 61 75 6e 63 68 4d 75 74 65 78 00 } //01 00 
		$a_01_1 = {67 61 74 65 77 61 79 2e 6d 65 73 73 65 6e 67 65 72 2e 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //01 00  gateway.messenger.hotmail.com
		$a_01_2 = {72 6b 5f 63 74 72 6c 5f 6e 6f 69 64 6c 65 33 32 } //01 00  rk_ctrl_noidle32
		$a_01_3 = {5f 5f 49 54 53 4e 4f 54 52 4f 4f 4d 5f 5f } //00 00  __ITSNOTROOM__
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_SpyLanternKeylogger_3{
	meta:
		description = "MonitoringTool:Win32/SpyLanternKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {25 73 5c 50 49 50 45 5c 25 73 5f 63 74 72 6c 00 90 02 10 5c 5c 25 73 5c 50 49 50 45 5c 25 73 5f 64 61 74 61 25 75 00 90 00 } //01 00 
		$a_02_1 = {53 70 79 20 4c 61 6e 74 65 72 6e 20 4b 65 79 6c 6f 67 67 65 72 00 90 02 10 25 73 5f 68 6b 6d 61 70 00 90 02 10 25 73 5c 64 62 00 00 90 00 } //01 00 
		$a_02_2 = {53 70 79 20 4c 61 6e 74 65 72 6e 20 4b 65 79 6c 6f 67 67 65 72 5c 90 02 35 3c 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 3e 90 02 20 3c 55 6e 69 71 49 44 20 6e 61 6d 65 3d 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}