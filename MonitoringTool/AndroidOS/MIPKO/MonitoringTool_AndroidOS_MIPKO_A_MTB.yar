
rule MonitoringTool_AndroidOS_MIPKO_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MIPKO.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 49 50 4b 4f 20 4d 4f 4e 49 54 4f 52 } //01 00  MIPKO MONITOR
		$a_01_1 = {45 6e 61 62 6c 65 4d 6f 6e 69 74 6f 72 } //01 00  EnableMonitor
		$a_01_2 = {45 6e 61 62 6c 65 43 6f 6e 74 61 63 74 73 } //01 00  EnableContacts
		$a_01_3 = {45 6e 61 62 6c 65 43 68 61 74 73 } //01 00  EnableChats
		$a_01_4 = {45 6e 61 62 6c 65 53 4d 53 } //01 00  EnableSMS
		$a_01_5 = {48 49 44 45 5f 50 41 53 53 57 4f 52 44 } //01 00  HIDE_PASSWORD
		$a_01_6 = {52 63 4f 74 67 43 6c 6c } //00 00  RcOtgCll
	condition:
		any of ($a_*)
 
}