
rule MonitoringTool_AndroidOS_Bulgok_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Bulgok.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 62 75 6c 67 61 6b 6f 76 2e 63 6f 6e 74 72 6f 6c 70 68 6f 6e 65 } //01 00  com.bulgakov.controlphone
		$a_00_1 = {63 61 6c 6c 5f 72 65 63 6f 72 64 69 6e 67 } //01 00  call_recording
		$a_00_2 = {48 49 53 54 4f 52 59 5f 53 4d 53 } //01 00  HISTORY_SMS
		$a_00_3 = {55 50 44 41 54 45 5f 48 49 53 5f 43 41 4c 4c } //01 00  UPDATE_HIS_CALL
		$a_00_4 = {75 70 64 61 74 65 52 65 63 53 6d 73 4c 6f 63 } //01 00  updateRecSmsLoc
		$a_00_5 = {75 70 64 61 74 65 48 69 73 43 61 6c 6c 43 6f 6e 74 61 63 74 } //01 00  updateHisCallContact
		$a_00_6 = {53 45 4e 44 5f 52 45 43 4f 52 44 5f 53 4d 53 5f 4c 4f 43 41 54 49 4f 4e } //00 00  SEND_RECORD_SMS_LOCATION
	condition:
		any of ($a_*)
 
}