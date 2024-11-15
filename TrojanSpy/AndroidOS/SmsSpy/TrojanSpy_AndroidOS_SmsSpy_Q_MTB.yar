
rule TrojanSpy_AndroidOS_SmsSpy_Q_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsSpy.Q!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 64 68 72 75 76 2f 73 6d 73 72 65 63 65 76 69 65 72 } //1 com/dhruv/smsrecevier
		$a_01_1 = {45 78 63 65 70 74 69 6f 6e 20 73 6d 73 52 65 63 65 69 76 65 72 } //1 Exception smsReceiver
		$a_01_2 = {73 65 6e 64 65 72 4e 75 6d 3a } //1 senderNum:
		$a_01_3 = {73 74 61 72 74 75 70 4f 6e 42 6f 6f 74 55 70 52 65 63 65 69 76 65 72 } //1 startupOnBootUpReceiver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}