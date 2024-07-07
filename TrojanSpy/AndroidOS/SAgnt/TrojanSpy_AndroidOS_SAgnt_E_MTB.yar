
rule TrojanSpy_AndroidOS_SAgnt_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {53 70 79 53 63 72 65 65 6e 73 68 6f 74 73 } //1 SpyScreenshots
		$a_00_1 = {73 70 79 44 61 74 61 62 61 73 65 } //1 spyDatabase
		$a_00_2 = {74 74 70 73 3a 2f 2f 72 34 64 63 33 62 74 62 79 7a 69 70 30 65 64 6b 62 79 6b 62 31 71 74 65 75 6c 77 62 2e 64 65 2f } //1 ttps://r4dc3btbyzip0edkbykb1qteulwb.de/
		$a_00_3 = {67 65 74 41 63 74 69 76 65 53 75 62 73 63 72 69 70 74 69 6f 6e 49 6e 66 6f 4c 69 73 74 } //1 getActiveSubscriptionInfoList
		$a_00_4 = {66 69 6e 64 61 63 63 65 73 73 69 62 69 6c 69 74 79 6e 6f 64 65 69 6e 66 6f 73 62 79 76 69 65 77 69 64 } //1 findaccessibilitynodeinfosbyviewid
		$a_00_5 = {73 65 6e 64 44 61 74 61 54 6f 53 6f 63 6b 65 74 } //1 sendDataToSocket
		$a_00_6 = {69 73 5f 72 65 61 64 5f 73 6d 73 } //1 is_read_sms
		$a_00_7 = {73 61 76 65 63 61 6c 6c 6c 6f 67 73 74 6f 64 61 74 61 62 61 73 65 } //1 savecalllogstodatabase
		$a_00_8 = {63 6f 6e 74 61 63 74 73 44 61 74 61 } //1 contactsData
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=7
 
}