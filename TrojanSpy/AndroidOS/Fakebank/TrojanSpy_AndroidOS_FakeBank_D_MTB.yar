
rule TrojanSpy_AndroidOS_FakeBank_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeBank.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 61 76 65 70 65 72 73 6f 6e 61 6c 64 65 74 61 69 6c 73 5f 73 74 65 70 66 69 72 73 74 } //01 00  savepersonaldetails_stepfirst
		$a_01_1 = {63 6f 6d 2e 61 70 70 2e 6d 61 6e 61 67 65 72 2e 69 63 69 63 69 2e 73 65 72 76 69 63 65 2e 75 70 64 61 74 65 } //01 00  com.app.manager.icici.service.update
		$a_01_2 = {67 65 74 73 65 61 72 63 68 74 72 61 63 6b 69 6e 67 } //01 00  getsearchtracking
		$a_01_3 = {2f 69 6e 74 65 72 61 63 74 69 6f 6e 6c 61 62 2f 61 6e 64 72 6f 69 64 2d 6e 6f 74 69 66 69 63 61 74 69 6f 6e 2d 6c 6f 67 } //01 00  /interactionlab/android-notification-log
		$a_01_4 = {63 61 72 64 4e 6f 45 74 } //01 00  cardNoEt
		$a_01_5 = {63 63 76 45 74 } //01 00  ccvEt
		$a_01_6 = {75 70 64 61 } //00 00  upda
	condition:
		any of ($a_*)
 
}