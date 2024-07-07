
rule TrojanSpy_AndroidOS_Recal_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Recal.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 64 65 6c 65 74 65 } //1 calldelete
		$a_01_1 = {73 65 6e 64 53 4d 53 32 4c 6f 6e 67 } //1 sendSMS2Long
		$a_01_2 = {73 65 6e 64 48 74 74 70 47 65 74 4e 75 6d 62 65 72 73 } //1 sendHttpGetNumbers
		$a_01_3 = {73 65 6e 64 48 74 74 70 47 65 74 4d 73 67 73 } //1 sendHttpGetMsgs
		$a_01_4 = {49 6d 48 65 72 65 52 65 63 65 69 76 65 72 } //1 ImHereReceiver
		$a_01_5 = {63 6d 64 5f 67 65 74 63 6f 6e 74 61 63 74 } //1 cmd_getcontact
		$a_00_6 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 63 61 6c 6c 72 65 63 6f 72 64 65 72 } //10 Lcom/example/callrecorder
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*10) >=15
 
}