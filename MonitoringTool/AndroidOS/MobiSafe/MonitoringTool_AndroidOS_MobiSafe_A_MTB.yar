
rule MonitoringTool_AndroidOS_MobiSafe_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MobiSafe.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 53 6d 73 53 61 66 65 41 63 74 69 76 69 74 79 } //1 CallSmsSafeActivity
		$a_01_1 = {6c 76 5f 63 61 6c 6c 73 6d 73 5f 73 61 66 65 } //1 lv_callsms_safe
		$a_01_2 = {6c 6c 5f 61 64 64 5f 6e 75 6d 62 65 72 5f 74 69 70 73 } //1 ll_add_number_tips
		$a_01_3 = {43 61 6c 6c 4c 6f 67 4f 62 73 65 72 76 65 72 } //1 CallLogObserver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}