
rule TrojanSpy_AndroidOS_Banker_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 42 67 53 65 72 76 69 63 65 3b } //2 /BgService;
		$a_00_1 = {53 6d 73 4c 69 73 74 65 6e 65 72 } //1 SmsListener
		$a_00_2 = {68 61 6e 64 6c 65 49 6e 63 6f 6d 69 6e 67 53 4d 53 } //1 handleIncomingSMS
		$a_00_3 = {63 61 6c 6c 74 72 61 6e 73 66 65 72 72 65 64 6c 69 73 74 } //1 calltransferredlist
		$a_00_4 = {63 61 6c 6c 63 6f 6e 74 61 63 74 73 } //1 callcontacts
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule TrojanSpy_AndroidOS_Banker_C_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 6c 75 67 73 2e 73 74 61 72 74 42 61 6e 6b 69 6e 67 42 6c 6f 63 6b 65 72 } //1 Plugs.startBankingBlocker
		$a_00_1 = {2f 73 79 73 74 65 6d 5f 75 70 64 61 74 65 2e 61 70 6b } //1 /system_update.apk
		$a_00_2 = {62 61 6e 6b 2e 68 74 6d 6c } //1 bank.html
		$a_00_3 = {68 69 64 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 hideNotification
		$a_00_4 = {6d 73 67 4c 69 73 74 53 65 6e 64 } //1 msgListSend
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}