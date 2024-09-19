
rule MonitoringTool_AndroidOS_DroidWatcher_D_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/DroidWatcher.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 77 61 74 63 68 6d 79 64 72 6f 69 64 2f 72 65 63 65 69 76 65 72 73 } //1 com/watchmydroid/receivers
		$a_01_1 = {4b 61 74 65 5f 6d 65 73 73 61 67 65 73 2e 64 62 } //1 Kate_messages.db
		$a_01_2 = {4f 75 74 67 6f 69 6e 67 43 61 6c 6c 52 65 63 65 69 76 65 72 } //1 OutgoingCallReceiver
		$a_01_3 = {52 45 43 4f 52 44 5f 43 41 4c 4c 53 } //1 RECORD_CALLS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}