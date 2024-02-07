
rule MonitoringTool_AndroidOS_Vionica_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Vionica.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 61 6b 65 50 69 63 74 75 72 65 49 6e 50 69 63 74 75 72 65 41 63 74 69 76 69 74 79 } //01 00  FakePictureInPictureActivity
		$a_01_1 = {4c 63 6f 6d 2f 76 69 6f 6e 69 6b 61 2f 6d 6f 62 69 76 65 6d 65 6e 74 } //01 00  Lcom/vionika/mobivement
		$a_01_2 = {4f 55 54 47 4f 49 4e 47 5f 43 41 4c 4c 5f 4e 55 4d 42 45 52 } //01 00  OUTGOING_CALL_NUMBER
		$a_01_3 = {6b 65 79 6c 6f 67 67 65 72 73 5f 6d 6f 6e 69 74 6f 72 69 6e 67 } //01 00  keyloggers_monitoring
		$a_01_4 = {70 72 65 76 65 6e 74 5f 75 6e 69 6e 73 74 61 6c 6c 61 74 69 6f 6e } //00 00  prevent_uninstallation
	condition:
		any of ($a_*)
 
}