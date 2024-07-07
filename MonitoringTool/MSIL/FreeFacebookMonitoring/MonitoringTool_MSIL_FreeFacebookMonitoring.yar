
rule MonitoringTool_MSIL_FreeFacebookMonitoring{
	meta:
		description = "MonitoringTool:MSIL/FreeFacebookMonitoring,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 00 72 00 65 00 65 00 20 00 46 00 61 00 63 00 65 00 62 00 6f 00 6f 00 6b 00 20 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 } //1 Free Facebook Monitoring
		$a_01_1 = {4b 00 65 00 79 00 20 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 4c 00 6f 00 67 00 20 00 66 00 69 00 6c 00 65 00 20 00 21 00 } //1 Key logger Log file !
		$a_01_2 = {41 00 75 00 74 00 6f 00 6d 00 61 00 74 00 69 00 63 00 61 00 6c 00 6c 00 79 00 20 00 65 00 6d 00 61 00 69 00 6c 00 20 00 72 00 65 00 73 00 75 00 6c 00 74 00 20 00 6c 00 6f 00 67 00 20 00 66 00 69 00 6c 00 65 00 } //1 Automatically email result log file
		$a_01_3 = {54 00 6f 00 20 00 72 00 65 00 74 00 75 00 72 00 6e 00 20 00 66 00 72 00 6f 00 6d 00 20 00 68 00 69 00 64 00 64 00 65 00 6e 00 20 00 6d 00 6f 00 64 00 65 00 20 00 70 00 72 00 65 00 73 00 73 00 20 00 43 00 74 00 72 00 6c 00 2b 00 41 00 6c 00 74 00 2b 00 53 00 68 00 69 00 66 00 74 00 } //1 To return from hidden mode press Ctrl+Alt+Shift
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}