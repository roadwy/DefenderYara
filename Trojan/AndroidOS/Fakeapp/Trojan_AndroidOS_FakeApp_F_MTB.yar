
rule Trojan_AndroidOS_FakeApp_F_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeApp.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6d 73 53 75 63 63 65 73 73 41 63 74 69 76 69 74 79 } //01 00  SmsSuccessActivity
		$a_01_1 = {73 6d 73 2e 70 68 70 3f 69 64 3d } //01 00  sms.php?id=
		$a_01_2 = {53 65 6e 64 65 72 53 65 72 76 69 63 65 } //01 00  SenderService
		$a_01_3 = {2f 61 70 69 2f 73 6d 73 2d 74 65 73 74 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 } //01 00  /api/sms-test/install.php
		$a_01_4 = {53 6d 73 54 65 73 74 65 72 } //01 00  SmsTester
		$a_01_5 = {67 65 74 49 6e 63 6f 6d 69 6e 67 4d 65 73 73 61 67 65 } //00 00  getIncomingMessage
	condition:
		any of ($a_*)
 
}