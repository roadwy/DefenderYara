
rule TrojanSpy_AndroidOS_SAgnt_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 06 0a 00 83 66 cd 64 8a 44 b7 04 71 20 ?? 00 42 00 0c 02 71 10 ?? ?? 02 00 0c 02 d8 00 00 01 28 ?? 71 20 } //1
		$a_01_1 = {45 69 72 76 41 70 70 43 6f 6d 70 6f 6e 65 6e 74 46 61 63 74 6f 72 79 53 74 75 62 } //1 EirvAppComponentFactoryStub
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanSpy_AndroidOS_SAgnt_D_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6e 74 61 63 74 73 2e 6a 73 6f 6e } //1 contacts.json
		$a_00_1 = {73 6d 73 2e 6a 73 6f 6e } //1 sms.json
		$a_00_2 = {67 65 74 43 61 6c 6c 73 4c 6f 67 73 } //1 getCallsLogs
		$a_00_3 = {67 65 74 53 4d 53 } //1 getSMS
		$a_00_4 = {67 65 74 43 6f 6e 74 61 63 74 73 } //1 getContacts
		$a_00_5 = {4c 63 6f 6d 2f 63 72 2f 63 68 61 74 2f 61 63 74 69 76 69 74 69 65 73 } //1 Lcom/cr/chat/activities
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}