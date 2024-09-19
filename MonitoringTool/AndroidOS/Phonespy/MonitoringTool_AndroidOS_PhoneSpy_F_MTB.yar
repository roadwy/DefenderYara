
rule MonitoringTool_AndroidOS_PhoneSpy_F_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/PhoneSpy.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 70 68 6f 6e 65 5f 74 72 61 5f 61 70 70 5f 73 70 2f 61 6c 65 72 74 } //1 com/phone_tra_app_sp/alert
		$a_01_1 = {53 63 72 65 65 6e 43 68 61 6e 63 65 64 52 65 63 65 69 76 65 72 } //1 ScreenChancedReceiver
		$a_01_2 = {41 63 74 76 5f 6f 74 68 65 72 } //1 Actv_other
		$a_01_3 = {52 65 63 5f 6f 74 68 65 72 } //1 Rec_other
		$a_01_4 = {43 61 6c 6c 52 65 63 6f 72 64 69 6e 67 53 65 72 76 69 63 65 } //1 CallRecordingService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}