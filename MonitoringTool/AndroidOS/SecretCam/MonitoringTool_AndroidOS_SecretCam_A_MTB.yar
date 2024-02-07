
rule MonitoringTool_AndroidOS_SecretCam_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SecretCam.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 68 6f 75 73 65 2f 61 70 70 73 2f 73 65 63 72 65 74 63 61 6d 63 6f 72 64 65 72 } //01 00  com/house/apps/secretcamcorder
		$a_01_1 = {4c 69 73 74 56 69 64 65 6f 41 63 74 69 76 69 74 79 } //01 00  ListVideoActivity
		$a_01_2 = {74 6b 74 65 63 68 73 69 74 65 2e 63 6f 6d 2f 6d 79 61 64 73 } //01 00  tktechsite.com/myads
		$a_01_3 = {51 75 69 63 6b 52 65 63 6f 72 64 69 6e 67 } //00 00  QuickRecording
	condition:
		any of ($a_*)
 
}