
rule MonitoringTool_MSIL_SilentMonitoring{
	meta:
		description = "MonitoringTool:MSIL/SilentMonitoring,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 47 65 74 49 6d 61 67 65 73 53 75 72 76 65 69 6c 6c 61 6e 63 65 4d 65 74 68 6f 64 } //1 CGetImagesSurveillanceMethod
		$a_01_1 = {43 4b 65 79 4c 6f 67 67 65 72 53 75 72 76 65 69 6c 6c 61 6e 63 65 4d 65 74 68 6f 64 } //1 CKeyLoggerSurveillanceMethod
		$a_01_2 = {43 57 65 62 73 69 74 65 73 4c 6f 67 67 65 72 4d 65 74 68 6f 64 } //1 CWebsitesLoggerMethod
		$a_01_3 = {73 00 69 00 6c 00 65 00 6e 00 74 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 } //1 silentmonitoring.com
		$a_01_4 = {73 00 68 00 6f 00 6d 00 65 00 72 00 2e 00 63 00 6f 00 2e 00 69 00 6c 00 } //1 shomer.co.il
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}