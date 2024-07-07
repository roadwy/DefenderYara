
rule MonitoringTool_AndroidOS_Traca_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Traca.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {54 72 61 63 6b 69 6e 67 43 6f 6e 74 72 6f 6c 6c 65 72 } //1 TrackingController
		$a_01_1 = {48 69 64 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e 53 65 72 76 69 63 65 } //1 HideNotificationService
		$a_01_2 = {74 72 61 63 63 61 72 2e 64 62 } //1 traccar.db
		$a_01_3 = {73 74 6f 70 54 72 61 63 6b 69 6e 67 53 65 72 76 69 63 65 } //1 stopTrackingService
		$a_01_4 = {4c 6f 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //1 LocationListener
		$a_01_5 = {72 65 6d 6f 76 65 4c 61 75 6e 63 68 65 72 49 63 6f 6e } //1 removeLauncherIcon
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}