
rule TrojanSpy_AndroidOS_SAgnt_AG_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AG!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 73 65 6e 64 4d 65 73 73 61 67 65 3f } //1 /sendMessage?
		$a_01_1 = {73 65 6e 64 44 6f 63 75 6d 65 6e 74 54 6f 43 68 61 6e 6e 65 6c } //1 sendDocumentToChannel
		$a_01_2 = {67 65 74 41 63 74 69 76 65 53 75 62 73 63 72 69 70 74 69 6f 6e 49 6e 66 6f 4c 69 73 74 } //1 getActiveSubscriptionInfoList
		$a_01_3 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 76 69 64 65 6f 63 68 61 74 2f 4d 65 73 73 61 67 65 52 65 63 65 69 76 65 72 } //1 com/example/videochat/MessageReceiver
		$a_01_4 = {2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //1 /api.telegram.org/bot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}