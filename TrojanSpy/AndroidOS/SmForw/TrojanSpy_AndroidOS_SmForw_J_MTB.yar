
rule TrojanSpy_AndroidOS_SmForw_J_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 6d 73 52 65 63 65 69 76 65 72 55 72 6c } //1 smsReceiverUrl
		$a_01_1 = {73 65 6e 74 41 64 4d 65 73 73 61 67 65 } //1 sentAdMessage
		$a_01_2 = {44 6f 41 66 74 65 72 52 65 63 65 69 76 65 4d 61 69 6c 4c 69 73 74 65 6e 65 72 } //1 DoAfterReceiveMailListener
		$a_01_3 = {67 65 74 41 6c 6c 48 69 73 74 6f 72 79 43 61 63 68 65 } //1 getAllHistoryCache
		$a_01_4 = {52 65 63 69 76 65 4f 6e 65 4d 61 69 6c } //1 ReciveOneMail
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}