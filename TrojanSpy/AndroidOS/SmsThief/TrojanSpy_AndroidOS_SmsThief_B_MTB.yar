
rule TrojanSpy_AndroidOS_SmsThief_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 41 70 6b 45 64 69 74 6f 72 73 2f 48 61 63 6b 69 6e 67 54 65 6c 65 67 72 61 6d 2f 49 6e 63 6f 6d 69 6e 67 53 6d 73 } //3 Lcom/ApkEditors/HackingTelegram/IncomingSms
		$a_00_1 = {67 65 74 44 69 73 70 6c 61 79 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getDisplayMessageBody
		$a_00_2 = {64 65 62 75 67 67 65 72 50 61 63 6b 61 67 65 4e 61 6d 65 } //1 debuggerPackageName
		$a_00_3 = {73 65 6e 64 65 72 4e 75 6d 3a } //1 senderNum:
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}