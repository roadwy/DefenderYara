
rule MonitoringTool_Win32_BRMonitor{
	meta:
		description = "MonitoringTool:Win32/BRMonitor,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 65 6c 61 74 6f 72 69 6f 2e 68 74 6d } //01 00 
		$a_00_1 = {4d 53 4e 4d 6f 6e 53 6e 69 66 66 65 72 4d 65 73 73 61 67 65 } //01 00 
		$a_03_2 = {be 01 00 00 00 33 c0 8a 84 35 90 01 02 ff ff 33 c3 89 45 f0 3b 7d f0 7c 0f 8b 45 f0 05 ff 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}