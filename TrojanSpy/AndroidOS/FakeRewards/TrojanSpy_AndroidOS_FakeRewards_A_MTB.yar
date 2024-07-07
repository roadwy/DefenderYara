
rule TrojanSpy_AndroidOS_FakeRewards_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeRewards.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {72 65 61 64 4c 61 74 65 73 74 4d 65 73 73 61 67 65 3a 20 6e 65 77 20 63 68 69 6c 64 20 6e 61 6d 65 } //1 readLatestMessage: new child name
		$a_00_1 = {66 65 74 63 68 53 4d 53 4d 65 73 73 61 67 65 73 } //1 fetchSMSMessages
		$a_00_2 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f 69 6e 62 6f 78 } //1 content://sms/inbox
		$a_00_3 = {69 73 50 61 63 6b 61 67 65 49 6e 73 74 61 6c 6c 65 64 3a 20 6c 69 6e 6b 69 6e 67 } //1 isPackageInstalled: linking
		$a_00_4 = {63 61 6c 6c 4c 6f 67 69 6e 41 63 74 69 76 69 74 79 3a 20 41 70 70 20 75 72 6c 20 65 71 75 61 6c } //1 callLoginActivity: App url equal
		$a_00_5 = {63 61 6c 6c 4c 6f 67 69 6e 41 63 74 69 76 69 74 79 3a 20 68 74 74 70 3a 2f 2f 6f 6e 6c 69 6e 65 77 73 76 2e 63 6f 6d 2f 61 70 70 73 2f 69 63 66 69 6c 65 73 2f } //1 callLoginActivity: http://onlinewsv.com/apps/icfiles/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}