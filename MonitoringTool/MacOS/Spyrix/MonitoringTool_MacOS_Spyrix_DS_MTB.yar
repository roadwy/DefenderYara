
rule MonitoringTool_MacOS_Spyrix_DS_MTB{
	meta:
		description = "MonitoringTool:MacOS/Spyrix.DS!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 70 79 72 69 78 2e 53 50 53 63 72 65 65 6e 73 68 6f 74 73 } //1 Spyrix.SPScreenshots
		$a_00_1 = {63 6f 6d 2e 73 70 79 72 69 78 2e 73 6b 6d } //1 com.spyrix.skm
		$a_00_2 = {2f 6d 6f 6e 69 74 6f 72 2f 69 75 70 6c 6f 61 64 2e 70 68 70 } //1 /monitor/iupload.php
		$a_00_3 = {73 74 61 72 74 4d 6f 6e 69 74 6f 72 69 6e 67 43 6c 69 70 62 6f 61 72 64 } //1 startMonitoringClipboard
		$a_00_4 = {43 61 6c 6c 52 65 63 6f 72 64 56 69 65 77 43 6f 6e 74 72 6f 6c 6c 65 72 } //1 CallRecordViewController
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}