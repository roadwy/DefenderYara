
rule TrojanSpy_AndroidOS_SAgnt_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {73 65 74 53 65 6e 64 74 6f 53 65 72 76 65 72 } //1 setSendtoServer
		$a_00_1 = {64 65 6c 69 76 65 72 53 65 6c 66 4e 6f 74 69 66 69 63 61 74 69 6f 6e 73 } //1 deliverSelfNotifications
		$a_00_2 = {43 6f 6e 74 61 63 74 73 4f 62 73 65 72 76 65 72 } //1 ContactsObserver
		$a_00_3 = {6e 65 77 53 6d 73 41 64 64 65 64 } //1 newSmsAdded
		$a_00_4 = {41 75 64 69 6f 52 65 63 6f 72 64 69 6e 67 53 65 72 76 69 63 65 } //1 AudioRecordingService
		$a_00_5 = {43 61 6c 6c 53 79 6e 63 53 65 72 76 69 63 65 } //1 CallSyncService
		$a_03_6 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f [0-18] 6d 6f 6e 69 74 6f 72 69 6e 67 2f 73 79 73 74 65 6d } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}