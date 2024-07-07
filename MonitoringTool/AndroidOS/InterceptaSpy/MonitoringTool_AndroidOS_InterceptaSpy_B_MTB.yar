
rule MonitoringTool_AndroidOS_InterceptaSpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/InterceptaSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 43 52 45 45 4e 5f 44 4f 4e 45 5f 4d 4f 4e 49 54 4f 52 } //1 SCREEN_DONE_MONITOR
		$a_01_1 = {69 73 5f 6e 6f 74 69 66 5f 61 74 69 76 65 } //1 is_notif_ative
		$a_01_2 = {4f 6e 49 6e 66 6f 4c 69 73 74 65 6e 65 72 } //1 OnInfoListener
		$a_01_3 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 73 79 73 74 65 6d 2f 61 63 74 69 76 74 73 2f 47 65 74 44 61 74 61 52 65 63 41 63 74 69 76 69 74 79 } //1 Lcom/android/system/activts/GetDataRecActivity
		$a_01_4 = {53 65 72 76 69 63 65 4d 6f 6e 69 74 6f 72 } //1 ServiceMonitor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}