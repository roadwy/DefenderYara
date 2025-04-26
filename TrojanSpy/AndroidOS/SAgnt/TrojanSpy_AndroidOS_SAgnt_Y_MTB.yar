
rule TrojanSpy_AndroidOS_SAgnt_Y_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.Y!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 70 70 66 6f 6c 69 78 2f 66 69 72 65 62 61 73 65 64 65 6d 6f 2f 73 65 72 76 69 63 65 73 } //1 com/appfolix/firebasedemo/services
		$a_01_1 = {57 41 43 6f 6e 74 61 63 74 73 4c 69 73 74 41 64 61 70 74 65 72 } //1 WAContactsListAdapter
		$a_01_2 = {75 70 6c 6f 61 64 4d 6f 62 69 6c 65 4e 75 6d 62 65 72 } //1 uploadMobileNumber
		$a_01_3 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 53 65 72 76 69 63 65 } //1 NotificationListenerService
		$a_01_4 = {67 65 74 4d 65 73 73 61 67 65 54 69 6d 65 } //1 getMessageTime
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}