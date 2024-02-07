
rule MonitoringTool_Win32_SpyAgent_A{
	meta:
		description = "MonitoringTool:Win32/SpyAgent.A,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 09 00 00 0a 00 "
		
	strings :
		$a_02_0 = {4f 4c 45 41 43 43 2e 64 6c 6c 90 02 04 3c 2f 48 54 4d 4c 3e 90 00 } //0a 00 
		$a_00_1 = {57 4d 5f 48 54 4d 4c 5f 47 45 54 4f 42 4a 45 43 54 } //0a 00  WM_HTML_GETOBJECT
		$a_00_2 = {4e 65 6f 4c 69 74 65 20 45 78 65 63 75 74 61 62 6c 65 20 46 69 6c 65 20 43 6f 6d 70 72 65 73 73 6f 72 } //01 00  NeoLite Executable File Compressor
		$a_00_3 = {47 72 61 62 41 4f 4c 55 52 4c } //01 00  GrabAOLURL
		$a_00_4 = {47 72 61 62 42 72 6f 77 73 65 72 55 52 4c } //01 00  GrabBrowserURL
		$a_00_5 = {47 72 61 62 46 69 72 65 46 6f 78 55 52 4c } //01 00  GrabFireFoxURL
		$a_00_6 = {47 72 61 62 4d 53 4e 53 6f 75 72 63 65 } //01 00  GrabMSNSource
		$a_00_7 = {47 72 61 62 53 6f 75 72 63 65 54 6f 46 69 6c 65 } //01 00  GrabSourceToFile
		$a_00_8 = {47 72 61 62 53 6f 75 72 63 65 } //00 00  GrabSource
	condition:
		any of ($a_*)
 
}