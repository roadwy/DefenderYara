
rule TrojanSpy_AndroidOS_Malaspy_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Malaspy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6d 61 6c 61 73 70 79 } //01 00  com.malaspy
		$a_01_1 = {53 70 79 44 72 6f 69 64 44 62 41 64 61 70 74 65 72 } //01 00  SpyDroidDbAdapter
		$a_01_2 = {61 6c 65 72 74 49 66 4d 6f 6e 6b 65 79 } //01 00  alertIfMonkey
		$a_01_3 = {47 6d 61 69 6c 4d 65 73 73 61 67 65 73 4f 62 73 65 72 76 65 72 } //01 00  GmailMessagesObserver
		$a_01_4 = {53 65 6e 64 4b 65 65 70 41 6c 69 76 65 41 54 } //01 00  SendKeepAliveAT
		$a_01_5 = {42 72 6f 77 53 65 72 4f 62 73 65 72 76 65 72 } //01 00  BrowSerObserver
		$a_01_6 = {72 65 6d 6f 76 65 41 63 74 69 76 65 41 64 6d 69 6e } //00 00  removeActiveAdmin
	condition:
		any of ($a_*)
 
}