
rule MonitoringTool_AndroidOS_XnSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/XnSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 65 63 75 74 65 55 70 6c 6f 61 64 } //01 00  executeUpload
		$a_01_1 = {53 4d 53 20 6c 6f 67 20 75 70 6c 6f 61 64 } //01 00  SMS log upload
		$a_01_2 = {58 4e 53 50 59 } //01 00  XNSPY
		$a_01_3 = {42 72 6f 77 73 65 69 6e 67 20 48 69 73 74 6f 72 79 20 65 78 65 63 75 74 65 42 61 63 6b 75 70 } //01 00  Browseing History executeBackup
		$a_01_4 = {63 6f 6e 74 61 63 74 4c 6f 67 42 61 63 6b 75 70 } //01 00  contactLogBackup
		$a_01_5 = {63 61 6c 6c 52 65 63 6f 72 64 69 6e 67 55 70 6c 6f 61 64 } //01 00  callRecordingUpload
		$a_01_6 = {75 70 64 61 74 65 49 6e 73 74 61 6c 6c 41 70 70 4c 6f 67 46 6f 72 53 79 6e 63 } //00 00  updateInstallAppLogForSync
	condition:
		any of ($a_*)
 
}