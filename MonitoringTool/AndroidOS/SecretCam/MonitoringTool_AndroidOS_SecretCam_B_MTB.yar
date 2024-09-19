
rule MonitoringTool_AndroidOS_SecretCam_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SecretCam.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 68 6f 75 73 65 2e 61 70 70 73 2e 73 65 63 72 65 74 63 61 6d 63 6f 72 64 65 72 } //5 com.house.apps.secretcamcorder
		$a_00_1 = {51 75 69 63 6b 52 65 63 6f 72 64 69 6e 67 45 6d 61 69 6c } //1 QuickRecordingEmail
		$a_00_2 = {41 55 54 4f 5f 52 45 43 4f 52 44 5f 57 48 45 4e 5f 55 4e 4c 4f 43 4b 5f 53 43 52 45 45 4e } //1 AUTO_RECORD_WHEN_UNLOCK_SCREEN
		$a_00_3 = {45 4e 41 42 4c 45 5f 52 45 43 4f 52 44 49 4e 47 5f 42 59 5f 53 4d 53 } //1 ENABLE_RECORDING_BY_SMS
		$a_00_4 = {43 61 6d 63 6f 72 64 65 72 50 72 6f 66 69 6c 65 } //1 CamcorderProfile
		$a_00_5 = {51 75 69 63 6b 52 65 63 6f 72 64 69 6e 67 52 65 63 6f 72 64 } //1 QuickRecordingRecord
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=8
 
}