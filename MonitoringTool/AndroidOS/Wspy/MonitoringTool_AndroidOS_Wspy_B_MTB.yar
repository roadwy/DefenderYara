
rule MonitoringTool_AndroidOS_Wspy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Wspy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 6f 64 65 6c 57 68 61 74 73 41 70 70 43 61 6c 6c } //01 00  modelWhatsAppCall
		$a_01_1 = {57 68 61 74 73 41 70 70 41 75 64 69 6f 57 6f 72 6b 65 72 } //01 00  WhatsAppAudioWorker
		$a_01_2 = {63 6f 6d 2f 73 64 6b 2f 6d 6f 64 75 6c 65 61 70 70 2f 41 70 70 } //01 00  com/sdk/moduleapp/App
		$a_01_3 = {50 68 6f 74 6f 50 68 6f 74 6f 54 61 6b 65 72 53 65 72 76 69 63 65 } //01 00  PhotoPhotoTakerService
		$a_01_4 = {6d 6f 64 61 6c 49 6e 73 74 61 67 72 61 6d 43 61 6c 6c } //00 00  modalInstagramCall
	condition:
		any of ($a_*)
 
}