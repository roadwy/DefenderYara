
rule TrojanSpy_AndroidOS_SAgnt_L_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 6d 6f 65 7a 2f 51 4b 53 4d 53 2f 69 6e 6a 65 63 74 69 6f 6e } //1 com/moez/QKSMS/injection
		$a_03_1 = {61 70 70 6d 65 73 73 61 67 67 69 32 30 32 32 2e 90 02 03 2f 61 70 70 90 00 } //1
		$a_01_2 = {68 69 64 65 46 72 6f 6d 4c 61 75 6e 63 68 65 72 } //1 hideFromLauncher
		$a_01_3 = {67 65 74 43 6f 6e 76 65 72 73 61 74 69 6f 6e 52 65 70 6f } //1 getConversationRepo
		$a_01_4 = {53 6d 73 52 65 63 65 69 76 65 72 5f 4d 65 6d 62 65 72 73 49 6e 6a 65 63 74 6f 72 } //1 SmsReceiver_MembersInjector
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}