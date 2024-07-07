
rule MonitoringTool_MacOS_Refog_TB_xp{
	meta:
		description = "MonitoringTool:MacOS/Refog.TB!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {52 65 66 6f 67 56 69 65 77 65 72 } //1 RefogViewer
		$a_00_1 = {73 6d 6f 6b 65 } //1 smoke
		$a_00_2 = {73 65 6e 64 43 6f 6d 6d 61 6e 64 3a 74 6f 56 69 65 77 65 72 4e 6f 74 4d 6f 6e 69 74 6f 72 } //1 sendCommand:toViewerNotMonitor
		$a_01_3 = {4d 41 53 65 63 4b 65 79 } //1 MASecKey
		$a_01_4 = {4d 41 53 68 79 } //1 MAShy
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}