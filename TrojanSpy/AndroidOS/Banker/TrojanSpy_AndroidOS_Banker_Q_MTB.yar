
rule TrojanSpy_AndroidOS_Banker_Q_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.Q!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 6d 73 2d 73 75 70 65 72 2d 72 61 74 2e 73 69 74 65 2f 69 6e 64 69 63 69 5f 66 75 6e 63 74 69 6f 6e 73 2e 70 68 70 } //01 00  sms-super-rat.site/indici_functions.php
		$a_00_1 = {75 70 6c 6f 61 64 4d 65 73 73 61 67 65 } //01 00  uploadMessage
		$a_00_2 = {73 65 6e 64 4c 69 73 74 41 70 70 } //01 00  sendListApp
		$a_00_3 = {4f 75 74 67 6f 69 6e 67 43 61 6c 6c 4c 69 73 74 } //01 00  OutgoingCallList
		$a_00_4 = {66 6f 72 77 61 72 64 69 6e 67 54 6f 41 70 6b } //00 00  forwardingToApk
	condition:
		any of ($a_*)
 
}