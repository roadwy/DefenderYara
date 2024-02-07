
rule MonitoringTool_AndroidOS_Spyoo_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Spyoo.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 68 65 74 72 75 74 68 73 70 79 2e 63 6f 6d } //01 00  thetruthspy.com
		$a_00_1 = {48 69 64 65 20 54 68 65 54 72 75 74 68 53 70 79 } //01 00  Hide TheTruthSpy
		$a_00_2 = {43 6f 6e 74 61 63 74 57 61 74 63 68 65 72 } //01 00  ContactWatcher
		$a_00_3 = {53 6d 73 57 61 74 63 68 65 72 } //01 00  SmsWatcher
		$a_00_4 = {43 61 6c 6c 57 61 74 63 68 65 72 } //01 00  CallWatcher
		$a_00_5 = {42 72 6f 77 73 69 6e 67 48 69 73 74 6f 72 79 57 61 74 63 68 65 72 } //00 00  BrowsingHistoryWatcher
	condition:
		any of ($a_*)
 
}