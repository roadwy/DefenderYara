
rule MonitoringTool_AndroidOS_ManaMon_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/ManaMon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 6d 73 49 6e 66 6f } //1 smsInfo
		$a_00_1 = {4d 53 47 5f 4f 55 54 42 4f 58 43 4f 4e 54 45 4e 54 } //1 MSG_OUTBOXCONTENT
		$a_00_2 = {55 50 4c 4f 41 44 5f 53 45 52 56 45 52 } //1 UPLOAD_SERVER
		$a_00_3 = {63 61 6c 6c 52 65 63 6f 72 64 49 6e 66 6f } //1 callRecordInfo
		$a_00_4 = {75 70 6c 6f 61 64 52 65 63 6f 64 65 72 } //1 uploadRecoder
		$a_00_5 = {6d 61 6e 61 67 65 72 69 5f 63 61 6c 6c 5f 73 65 6e 64 } //1 manageri_call_send
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}