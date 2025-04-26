
rule MonitoringTool_AndroidOS_Remosm_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Remosm.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 6d 73 5f 6c 6f 63 6b } //1 sms_lock
		$a_00_1 = {4c 63 6f 6d 2f 67 72 72 7a 7a 7a 2f 72 65 6d 6f 74 65 73 6d 73 66 75 6c 6c 2f 52 65 6d 6f 74 65 53 4d 53 } //1 Lcom/grrzzz/remotesmsfull/RemoteSMS
		$a_00_2 = {2f 63 61 63 68 65 2f 63 6f 6e 74 61 63 74 73 2e 64 61 74 } //1 /cache/contacts.dat
		$a_00_3 = {73 6d 73 5f 74 68 72 65 61 64 5f 64 65 6c 65 74 65 2e 68 74 6d } //1 sms_thread_delete.htm
		$a_00_4 = {73 6d 73 5f 6d 61 78 } //1 sms_max
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}