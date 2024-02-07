
rule MonitoringTool_AndroidOS_Aspy_E_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Aspy.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 61 73 2f 66 61 63 65 63 61 70 74 75 72 65 } //05 00  Lcom/as/facecapture
		$a_01_1 = {61 2d 73 70 79 } //01 00  a-spy
		$a_01_2 = {64 65 6c 65 74 65 64 61 6c 6c } //01 00  deletedall
		$a_01_3 = {68 69 64 65 5f 6e 6f 74 69 66 69 63 61 74 69 6f 6e } //01 00  hide_notification
		$a_01_4 = {73 74 61 72 74 5f 63 61 70 74 75 72 65 } //00 00  start_capture
	condition:
		any of ($a_*)
 
}