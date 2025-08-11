
rule MonitoringTool_MacOS_Refog_B_MTB{
	meta:
		description = "MonitoringTool:MacOS/Refog.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 68 6f 76 65 72 77 61 74 63 68 2e 6d 6f 6e 69 74 6f 72 } //1 com.hoverwatch.monitor
		$a_01_1 = {4d 41 43 68 61 74 47 72 61 62 62 65 72 } //1 MAChatGrabber
		$a_01_2 = {69 6e 73 74 61 6c 6c 65 64 4d 6f 6e 69 74 6f 72 55 52 4c } //1 installedMonitorURL
		$a_01_3 = {63 6f 6d 2e 68 77 2e 68 77 69 6e 73 74 61 6c 6c 65 72 } //1 com.hw.hwinstaller
		$a_01_4 = {6b 54 43 43 53 65 72 76 69 63 65 53 63 72 65 65 6e 43 61 70 74 75 72 65 } //1 kTCCServiceScreenCapture
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}