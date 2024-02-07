
rule MonitoringTool_AndroidOS_Xdspy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Xdspy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 65 73 73 61 67 65 53 63 72 61 70 70 65 72 } //01 00  MessageScrapper
		$a_01_1 = {54 4f 4b 45 4e 5f 48 41 43 4b 45 52 } //01 00  TOKEN_HACKER
		$a_01_2 = {67 65 74 73 6d 73 } //01 00  getsms
		$a_01_3 = {67 65 74 43 6f 6e 74 61 63 74 73 } //01 00  getContacts
		$a_01_4 = {67 65 74 43 61 6c 6c 73 4c 6f 67 73 } //01 00  getCallsLogs
		$a_01_5 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 41 70 70 73 } //01 00  getInstalledApps
		$a_01_6 = {78 64 2e 74 78 74 } //00 00  xd.txt
	condition:
		any of ($a_*)
 
}