
rule TrojanSpy_AndroidOS_FakeBank_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeBank.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 77 69 73 68 2f 64 65 66 61 75 6c 74 63 61 6c 6c 73 65 72 76 69 63 65 } //1 com/wish/defaultcallservice
		$a_01_1 = {41 70 70 49 6e 73 74 61 6c 6c 52 65 63 65 69 76 65 72 } //1 AppInstallReceiver
		$a_01_2 = {72 65 6d 6f 76 65 41 6c 6c 56 69 65 77 73 } //1 removeAllViews
		$a_01_3 = {6e 6f 74 69 66 69 63 61 74 69 6f 6e 54 69 6d 65 6f 75 74 } //1 notificationTimeout
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}