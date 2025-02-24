
rule TrojanSpy_AndroidOS_RewardSteal_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RewardSteal.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 4d 65 73 73 61 67 65 54 6f 54 65 6c 65 67 72 61 6d 42 6f 74 73 } //1 sendMessageToTelegramBots
		$a_01_1 = {70 72 6f 63 65 73 73 53 6d 73 52 65 63 65 69 76 65 64 } //1 processSmsReceived
		$a_01_2 = {66 65 74 63 68 46 6f 72 77 61 72 64 69 6e 67 4e 75 6d 62 65 72 } //1 fetchForwardingNumber
		$a_01_3 = {63 6f 6d 2f 63 66 68 64 2f 63 6f 6d 2f 53 4d 53 52 65 63 65 69 76 65 72 } //1 com/cfhd/com/SMSReceiver
		$a_01_4 = {69 6e 69 74 69 61 6c 69 7a 65 53 4d 53 46 6f 72 77 61 72 64 65 72 } //1 initializeSMSForwarder
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}