
rule TrojanSpy_AndroidOS_SmsCatch_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsCatch.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 6e 64 72 6f 69 64 5f 53 4d 53 2f 69 6e 73 74 61 6c 6c 69 6e 67 2e 70 68 70 } //01 00  Android_SMS/installing.php
		$a_00_1 = {73 6d 73 73 65 6e 64 69 6e 67 74 65 73 74 } //01 00  smssendingtest
		$a_00_2 = {61 72 72 61 79 4f 66 53 6d 73 4d 65 73 73 61 67 65 } //01 00  arrayOfSmsMessage
		$a_00_3 = {6e 75 6d 62 65 72 63 68 6b 31 } //01 00  numberchk1
		$a_00_4 = {63 61 74 63 68 53 4d 53 } //00 00  catchSMS
	condition:
		any of ($a_*)
 
}