
rule TrojanSpy_AndroidOS_Keylogger_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Keylogger.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 59 5f 50 52 45 46 53 5f 43 6c 69 63 6b 73 5f 43 6f 75 6e 74 5f 4b 45 59 } //01 00  MY_PREFS_Clicks_Count_KEY
		$a_01_1 = {67 65 74 53 59 53 49 6e 66 6f } //01 00  getSYSInfo
		$a_01_2 = {53 65 6e 64 31 73 74 4d 61 69 6c 54 61 73 6b } //01 00  Send1stMailTask
		$a_01_3 = {49 6e 47 53 65 72 76 69 63 65 } //00 00  InGService
	condition:
		any of ($a_*)
 
}