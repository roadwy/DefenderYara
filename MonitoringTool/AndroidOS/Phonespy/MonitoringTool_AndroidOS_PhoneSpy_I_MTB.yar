
rule MonitoringTool_AndroidOS_PhoneSpy_I_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/PhoneSpy.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 73 70 61 74 72 61 6b 61 70 70 70 2f 61 6c 61 72 6d 2f 61 63 74 69 76 69 74 69 65 73 2f 50 68 6f 6e 65 41 6c 72 65 61 64 79 52 65 67 69 73 74 65 72 65 64 } //1 Lcom/spatrakappp/alarm/activities/PhoneAlreadyRegistered
		$a_01_1 = {4c 63 6f 6d 2f 73 70 61 74 72 61 6b 61 70 70 70 2f 61 6c 61 72 6d 2f 61 63 74 69 76 69 74 69 65 73 2f 45 6e 61 62 6c 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e 41 63 63 65 73 73 } //1 Lcom/spatrakappp/alarm/activities/EnableNotificationAccess
		$a_01_2 = {4c 63 6f 6d 2f 73 70 61 74 72 61 6b 61 70 70 70 2f 61 6c 61 72 6d 2f 73 65 72 76 69 63 65 73 2f 52 65 6d 6f 74 65 52 65 63 6f 72 64 69 6e 67 53 65 72 76 69 63 65 } //1 Lcom/spatrakappp/alarm/services/RemoteRecordingService
		$a_01_3 = {4c 63 6f 6d 2f 73 70 61 74 72 61 6b 61 70 70 70 2f 61 6c 61 72 6d 2f 73 65 72 76 69 63 65 73 2f 54 72 61 63 6b 4c 6f 63 61 74 69 6f 6e } //1 Lcom/spatrakappp/alarm/services/TrackLocation
		$a_01_4 = {4c 63 6f 6d 2f 73 70 61 74 72 61 6b 61 70 70 70 2f 61 6c 61 72 6d 2f 53 65 72 76 65 72 43 6f 6d 6d 75 6e 69 63 61 74 65 } //1 Lcom/spatrakappp/alarm/ServerCommunicate
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}