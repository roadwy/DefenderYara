
rule MonitoringTool_AndroidOS_PhoneSpy_D_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/PhoneSpy.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,21 00 21 00 0c 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 61 73 2e 6d 6f 6e 69 74 6f 72 69 6e 67 61 70 70 2e 6c 6f 67 67 69 6e 67 } //10 com.as.monitoringapp.logging
		$a_00_1 = {43 61 6c 6c 52 65 63 6f 72 64 54 72 61 63 65 72 } //5 CallRecordTracer
		$a_00_2 = {43 68 72 6f 6d 65 48 69 73 74 6f 72 79 48 69 73 74 6f 72 79 } //5 ChromeHistoryHistory
		$a_00_3 = {53 74 6f 63 6b 20 42 72 6f 77 73 65 72 } //5 Stock Browser
		$a_00_4 = {43 61 6c 6c 48 69 73 74 6f 72 79 54 72 61 63 6b 65 72 } //5 CallHistoryTracker
		$a_00_5 = {72 65 61 64 5f 63 68 61 74 73 5f 6c 6f 67 73 } //5 read_chats_logs
		$a_01_6 = {53 65 6e 64 50 6f 73 74 5f 75 70 6c 6f 61 64 43 61 6c 65 6e 64 61 72 2e 74 78 74 } //1 SendPost_uploadCalendar.txt
		$a_01_7 = {53 65 6e 64 50 6f 73 74 5f 75 70 6c 6f 61 64 63 6f 6e 74 61 63 74 2e 74 78 74 } //1 SendPost_uploadcontact.txt
		$a_01_8 = {5f 69 6d 67 5f 6c 6f 67 73 5f 53 63 72 65 65 6e 53 68 6f 74 2e 74 78 74 } //1 _img_logs_ScreenShot.txt
		$a_01_9 = {42 6b 67 72 6f 75 6e 64 57 6f 72 6b 2e 74 78 74 } //1 BkgroundWork.txt
		$a_01_10 = {4e 6f 74 69 66 79 5f 73 7a 2e 74 78 74 } //1 Notify_sz.txt
		$a_01_11 = {43 61 6c 6c 72 65 63 6f 72 64 2e 74 78 74 } //1 Callrecord.txt
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_00_4  & 1)*5+(#a_00_5  & 1)*5+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=33
 
}