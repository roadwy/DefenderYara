
rule TrojanSpy_AndroidOS_Banker_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 08 00 00 02 00 "
		
	strings :
		$a_00_0 = {62 61 73 64 76 76 53 41 54 41 54 77 74 63 64 73 61 } //02 00  basdvvSATATwtcdsa
		$a_00_1 = {62 62 61 76 6f 50 72 73 73 77 } //01 00  bbavoPrssw
		$a_00_2 = {74 72 61 63 6b 5f 73 6d 73 } //01 00  track_sms
		$a_00_3 = {66 69 6e 64 41 63 63 65 73 73 69 62 69 6c 69 74 79 4e 6f 64 65 49 6e 66 6f 73 42 79 56 69 65 77 49 64 } //01 00  findAccessibilityNodeInfosByViewId
		$a_00_4 = {6c 6f 63 6b 73 63 72 } //01 00  lockscr
		$a_00_5 = {61 63 74 61 6c 6c 69 6e 6a } //01 00  actallinj
		$a_00_6 = {69 6e 73 74 61 70 70 73 } //01 00  instapps
		$a_00_7 = {6b 65 79 6c 6f 67 } //00 00  keylog
		$a_00_8 = {be a4 00 00 05 } //00 05 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_AndroidOS_Banker_F_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 53 70 61 6d 2f 53 65 72 76 69 63 65 53 65 6e 64 65 72 53 70 61 6d 53 4d 53 } //01 00  /Spam/ServiceSenderSpamSMS
		$a_00_1 = {41 63 74 69 76 69 74 79 46 61 6b 65 41 70 70 53 74 61 72 74 } //01 00  ActivityFakeAppStart
		$a_00_2 = {41 63 74 69 76 69 74 79 53 63 72 65 65 6e 4c 6f 63 6b 65 72 } //01 00  ActivityScreenLocker
		$a_00_3 = {53 65 72 76 69 63 65 43 72 79 70 74 46 69 6c 65 73 } //01 00  ServiceCryptFiles
		$a_00_4 = {53 65 72 76 69 63 65 50 6c 61 79 50 72 6f 74 65 63 74 54 6f 61 73 74 } //01 00  ServicePlayProtectToast
		$a_00_5 = {50 75 73 68 49 6e 6a 65 63 74 69 6f 6e } //01 00  PushInjection
		$a_00_6 = {47 65 74 53 4d 53 } //00 00  GetSMS
		$a_00_7 = {5d 04 00 } //00 5d 
	condition:
		any of ($a_*)
 
}