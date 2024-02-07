
rule MonitoringTool_AndroidOS_Aspy_H_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Aspy.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 67 6c 5f 42 72 6f 61 64 63 61 73 74 } //01 00  kgl_Broadcast
		$a_01_1 = {61 73 6b 5f 64 65 6c 65 74 65 5f 61 6c 6c } //01 00  ask_delete_all
		$a_01_2 = {61 63 74 69 76 61 74 65 5f 61 63 63 5f 6d 65 73 73 61 67 65 } //01 00  activate_acc_message
		$a_01_3 = {61 70 6b 2e 6b 67 6c } //00 00  apk.kgl
	condition:
		any of ($a_*)
 
}