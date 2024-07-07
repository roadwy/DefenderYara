
rule MonitoringTool_AndroidOS_GPTrak_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/GPTrak.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {6f 72 67 2e 74 72 61 63 63 61 72 2e 63 6c 69 65 6e 74 } //1 org.traccar.client
		$a_01_1 = {73 74 61 72 74 55 70 64 61 74 65 73 } //1 startUpdates
		$a_01_2 = {72 65 6d 6f 76 65 4c 61 75 6e 63 68 65 72 49 63 6f 6e } //1 removeLauncherIcon
		$a_01_3 = {73 74 61 72 74 54 72 61 63 6b 69 6e 67 53 65 72 76 69 63 65 } //1 startTrackingService
		$a_01_4 = {70 72 6f 63 65 73 73 4c 6f 63 61 74 69 6f 6e } //1 processLocation
		$a_01_5 = {48 69 64 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e 53 65 72 76 69 63 65 } //1 HideNotificationService
		$a_01_6 = {54 72 61 63 6b 69 6e 67 43 6f 6e 74 72 6f 6c 6c 65 72 } //1 TrackingController
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}