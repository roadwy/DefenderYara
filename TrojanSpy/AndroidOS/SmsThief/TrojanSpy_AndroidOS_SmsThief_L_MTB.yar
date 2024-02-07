
rule TrojanSpy_AndroidOS_SmsThief_L_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 72 65 61 6c 73 70 79 2f } //02 00  /realspy/
		$a_00_1 = {2f 72 65 61 6c 72 61 74 2f } //01 00  /realrat/
		$a_00_2 = {73 6d 73 74 6f 63 6f 6e 74 61 63 74 73 } //01 00  smstocontacts
		$a_00_3 = {68 69 64 65 61 70 6b } //01 00  hideapk
		$a_00_4 = {63 6f 6e 74 61 63 74 73 2e 74 78 74 } //01 00  contacts.txt
		$a_00_5 = {53 4d 53 49 6e 74 65 72 63 65 70 74 6f 72 } //01 00  SMSInterceptor
		$a_00_6 = {70 6f 73 74 5f 64 61 74 61 } //00 00  post_data
		$a_00_7 = {be 85 00 00 06 } //00 06 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_AndroidOS_SmsThief_L_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 4b 72 79 70 74 6f 73 6d 73 3b } //01 00  /Kryptosms;
		$a_00_1 = {2f 41 75 74 6f 53 65 72 76 69 63 65 3b } //01 00  /AutoService;
		$a_00_2 = {2f 4c 75 6b 61 73 } //01 00  /Lukas
		$a_00_3 = {66 69 6e 64 41 63 63 65 73 73 69 62 69 6c 69 74 79 4e 6f 64 65 49 6e 66 6f 73 42 79 56 69 65 77 49 64 } //01 00  findAccessibilityNodeInfosByViewId
		$a_00_4 = {67 65 74 44 69 73 70 6c 61 79 4d 65 73 73 61 67 65 42 6f 64 79 } //01 00  getDisplayMessageBody
		$a_00_5 = {70 65 72 66 6f 72 6d 41 63 74 69 6f 6e } //00 00  performAction
		$a_00_6 = {5d 04 00 00 } //ec 75 
	condition:
		any of ($a_*)
 
}