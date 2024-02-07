
rule MonitoringTool_Win32_SpyAgent_D{
	meta:
		description = "MonitoringTool:Win32/SpyAgent.D,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 70 79 74 65 63 68 20 53 70 79 41 67 65 6e 74 20 4b 65 79 73 74 72 6f 6b 65 } //01 00  Spytech SpyAgent Keystroke
		$a_01_1 = {25 73 73 61 63 61 63 68 65 5c 73 6b 65 79 73 2e 6c 6f 67 } //01 00  %ssacache\skeys.log
		$a_01_2 = {2d 2d 23 42 4f 55 4e 44 41 52 59 23 } //01 00  --#BOUNDARY#
		$a_01_3 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 74 65 78 74 2f 68 74 6d 6c 3b 20 6e 61 6d 65 3d 6c 6f 67 73 2e 74 78 74 } //00 00  Content-Type: text/html; name=logs.txt
	condition:
		any of ($a_*)
 
}