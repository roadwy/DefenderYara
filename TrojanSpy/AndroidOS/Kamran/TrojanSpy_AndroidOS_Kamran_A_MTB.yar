
rule TrojanSpy_AndroidOS_Kamran_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Kamran.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 6b 61 6d 72 61 6e 2f 68 75 6e 7a 61 6e 65 77 73 } //1 com/kamran/hunzanews
		$a_01_1 = {75 70 6c 6f 61 64 43 61 6c 6c 4c 6f 67 73 } //1 uploadCallLogs
		$a_01_2 = {68 75 6e 7a 61 6e 65 77 73 2e 6e 65 74 } //1 hunzanews.net
		$a_01_3 = {63 61 6c 6c 59 6f 75 74 75 62 65 } //1 callYoutube
		$a_01_4 = {66 65 74 63 68 49 73 43 6f 6e 74 61 63 74 73 41 64 64 65 64 } //1 fetchIsContactsAdded
		$a_01_5 = {75 70 6c 6f 61 64 4d 65 73 73 61 67 65 73 } //1 uploadMessages
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}