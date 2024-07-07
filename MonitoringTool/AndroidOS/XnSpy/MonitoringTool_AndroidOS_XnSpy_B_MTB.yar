
rule MonitoringTool_AndroidOS_XnSpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/XnSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 69 70 65 50 68 6f 6e 65 41 6e 64 53 63 72 65 65 6e 73 68 6f 74 } //1 wipePhoneAndScreenshot
		$a_01_1 = {43 6f 6e 74 61 63 74 57 61 74 63 68 4c 69 73 74 } //1 ContactWatchList
		$a_01_2 = {2f 70 61 79 6c 6f 61 64 2f 73 6d 73 64 65 74 61 69 6c } //1 /payload/smsdetail
		$a_01_3 = {2f 70 61 79 6c 6f 61 64 2f 69 6d 73 67 6c 6f 67 64 65 74 61 69 6c } //1 /payload/imsglogdetail
		$a_01_4 = {4c 63 6f 6d 2f 78 6e 73 70 79 2f 64 61 73 68 62 6f 61 72 64 } //1 Lcom/xnspy/dashboard
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}