
rule MonitoringTool_AndroidOS_Gizmo_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Gizmo.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 67 69 7a 6d 6f 71 75 69 70 2e 73 6d 73 74 72 61 63 6b 65 72 } //1 com.gizmoquip.smstracker
		$a_01_1 = {43 61 6c 6c 4c 6f 67 4f 62 73 65 72 76 65 72 } //1 CallLogObserver
		$a_01_2 = {53 6d 73 4f 62 73 65 72 76 65 72 } //1 SmsObserver
		$a_01_3 = {72 65 67 69 73 74 72 61 74 69 6f 6e 73 2e 73 6d 73 74 72 61 63 6b 65 72 2e 63 6f 6d } //1 registrations.smstracker.com
		$a_01_4 = {53 4d 53 54 72 61 63 6b 65 72 41 50 49 53 65 72 76 69 63 65 } //1 SMSTrackerAPIService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}