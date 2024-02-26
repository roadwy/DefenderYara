
rule MonitoringTool_MacOS_Spyrix_K_MTB{
	meta:
		description = "MonitoringTool:MacOS/Spyrix.K!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 73 70 79 72 69 78 2e 73 6b 6d } //01 00  com.spyrix.skm
		$a_00_1 = {6d 6f 6e 69 74 6f 72 2f 75 70 6c 6f 61 64 } //01 00  monitor/upload
		$a_00_2 = {2f 6d 6f 6e 69 74 6f 72 2f 69 75 70 6c 6f 61 64 } //01 00  /monitor/iupload
		$a_00_3 = {64 61 73 68 62 6f 61 72 64 2e 73 70 79 72 69 78 2e 63 6f 6d 2f } //01 00  dashboard.spyrix.com/
		$a_00_4 = {2f 4c 69 62 72 61 72 79 2f 73 6b 6d 2f 53 70 79 72 69 78 2e 61 70 70 } //00 00  /Library/skm/Spyrix.app
	condition:
		any of ($a_*)
 
}