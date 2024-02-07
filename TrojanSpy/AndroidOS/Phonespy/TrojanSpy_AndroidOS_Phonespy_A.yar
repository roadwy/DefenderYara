
rule TrojanSpy_AndroidOS_Phonespy_A{
	meta:
		description = "TrojanSpy:AndroidOS/Phonespy.A,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {75 70 6c 6f 61 64 43 61 6c 6c 4c 6f 67 73 } //02 00  uploadCallLogs
		$a_00_1 = {4c 41 53 54 5f 43 41 4c 4c 5f 4c 4f 47 5f 4e 55 4d } //02 00  LAST_CALL_LOG_NUM
		$a_00_2 = {41 4c 52 45 41 44 59 5f 48 49 44 45 5f 49 43 4f 4e } //02 00  ALREADY_HIDE_ICON
		$a_00_3 = {4c 41 53 54 5f 53 4d 53 5f 4e 55 4d } //00 00  LAST_SMS_NUM
	condition:
		any of ($a_*)
 
}