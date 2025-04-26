
rule MonitoringTool_AndroidOS_ImeiTracker_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/ImeiTracker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 4d 45 49 20 54 72 61 63 6b 65 72 20 52 65 63 65 69 76 65 72 } //1 IMEI Tracker Receiver
		$a_01_1 = {64 65 73 74 69 6e 61 74 69 6f 6e 50 68 6f 6e 65 4e 75 6d 62 65 72 } //1 destinationPhoneNumber
		$a_01_2 = {4c 63 6f 6d 2f 6c 67 65 2f 6c 67 6d 69 74 73 } //1 Lcom/lge/lgmits
		$a_01_3 = {4c 67 6d 69 74 73 52 65 63 65 69 76 65 72 } //1 LgmitsReceiver
		$a_01_4 = {6f 6e 49 6d 65 69 54 72 61 63 6b 65 72 53 74 61 72 74 } //1 onImeiTrackerStart
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}