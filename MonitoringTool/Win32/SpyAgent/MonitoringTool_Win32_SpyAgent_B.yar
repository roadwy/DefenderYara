
rule MonitoringTool_Win32_SpyAgent_B{
	meta:
		description = "MonitoringTool:Win32/SpyAgent.B,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 53 70 79 74 65 63 68 } //01 00  SOFTWARE\Spytech
		$a_01_1 = {4e 65 6f 57 6f 72 78 } //01 00  NeoWorx
		$a_01_2 = {4b 65 79 73 74 72 6f 6b 65 43 6f 75 6e 74 } //01 00  KeystrokeCount
		$a_01_3 = {25 73 5c 73 61 63 61 63 68 65 5c 73 6b 65 79 73 25 64 2e 6c 6f 67 } //01 00  %s\sacache\skeys%d.log
		$a_01_4 = {5f 4a 6f 75 72 6e 61 6c 50 72 6f 63 40 31 32 } //00 00  _JournalProc@12
	condition:
		any of ($a_*)
 
}