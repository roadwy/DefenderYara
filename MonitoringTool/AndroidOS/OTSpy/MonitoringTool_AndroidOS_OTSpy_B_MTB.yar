
rule MonitoringTool_AndroidOS_OTSpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/OTSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 49 4c 45 4e 54 5f 42 41 43 4b 5f 43 41 4d 5f 50 41 53 53 57 4f 52 44 } //1 SILENT_BACK_CAM_PASSWORD
		$a_01_1 = {45 72 61 73 65 43 6f 6e 74 61 63 74 73 41 63 74 69 76 69 74 79 } //1 EraseContactsActivity
		$a_01_2 = {72 73 5f 73 69 6c 65 6e 74 5f 76 69 64 65 6f } //1 rs_silent_video
		$a_01_3 = {52 45 4d 4f 54 45 5f 43 4f 4e 54 41 43 54 5f 50 41 53 53 57 4f 52 44 } //1 REMOTE_CONTACT_PASSWORD
		$a_03_4 = {63 6f 6d 2e ?? ?? ?? 2e 72 65 6d 6f 74 65 73 65 63 75 72 69 74 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule MonitoringTool_AndroidOS_OTSpy_B_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/OTSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 65 6e 64 56 69 64 65 6f 41 6e 64 4c 6f 63 61 74 69 6f 6e 53 4d 53 54 61 73 6b } //1 SendVideoAndLocationSMSTask
		$a_01_1 = {73 65 6e 64 4c 43 50 53 4d 53 } //1 sendLCPSMS
		$a_01_2 = {53 65 6e 64 56 69 64 65 6f 41 6e 64 4c 6f 63 45 6d 61 69 6c 54 61 73 6b } //1 SendVideoAndLocEmailTask
		$a_01_3 = {54 72 61 63 6b 65 72 4c 6f 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //1 TrackerLocationListener
		$a_03_4 = {4c 63 6f 6d 2f [0-04] 6c 61 64 69 65 73 63 68 69 6c 64 70 72 6f 74 65 63 74 69 6f 6e 2f 61 63 74 69 76 69 74 69 65 73 } //5
		$a_01_5 = {4c 63 6f 6d 2f 6f 74 73 2f 77 6f 6d 65 6e 63 68 69 6c 64 73 61 66 65 74 79 } //5 Lcom/ots/womenchildsafety
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*5+(#a_01_5  & 1)*5) >=9
 
}