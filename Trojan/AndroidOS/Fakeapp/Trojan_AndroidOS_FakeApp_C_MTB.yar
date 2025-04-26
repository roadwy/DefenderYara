
rule Trojan_AndroidOS_FakeApp_C_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeApp.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 43 61 6c 6c 73 50 65 72 48 6f 73 74 } //1 getCallsPerHost
		$a_01_1 = {75 70 4c 6f 61 64 53 4d 53 4c 69 73 74 } //1 upLoadSMSList
		$a_01_2 = {67 65 74 4c 6f 67 69 6e 50 68 6f 6e 65 } //1 getLoginPhone
		$a_01_3 = {75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 73 } //1 uploadContacts
		$a_01_4 = {63 61 6e 63 65 6c 41 6c 6c 4e 6f 74 69 66 69 63 61 74 69 6f 6e 73 } //1 cancelAllNotifications
		$a_01_5 = {75 70 6c 6f 61 64 4c 6f 63 61 74 69 6f 6e } //1 uploadLocation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}