
rule TrojanSpy_AndroidOS_Lipizzan_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Lipizzan.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {66 65 74 63 68 43 6f 6e 74 61 63 74 73 } //1 fetchContacts
		$a_00_1 = {66 65 74 63 68 43 61 6c 6c 4c 6f 67 73 } //1 fetchCallLogs
		$a_00_2 = {66 65 74 63 68 53 6d 73 } //1 fetchSms
		$a_03_3 = {63 6f 6d 2f [0-18] 66 65 74 63 68 65 72 73 2f 46 65 74 63 68 65 72 73 4d 61 6e 61 67 65 72 } //1
		$a_00_4 = {67 65 74 45 6d 61 69 6c 73 } //1 getEmails
		$a_00_5 = {64 75 6d 70 44 61 74 61 54 6f 46 69 6c 65 } //1 dumpDataToFile
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}