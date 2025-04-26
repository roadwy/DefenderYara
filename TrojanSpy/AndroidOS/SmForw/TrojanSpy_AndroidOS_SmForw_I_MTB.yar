
rule TrojanSpy_AndroidOS_SmForw_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 78 69 6e 67 68 61 69 2f 73 6d 73 } //1 com/xinghai/sms
		$a_03_1 = {2e 63 6f 6d 2f [0-05] 2f 73 61 76 65 73 2e 70 68 70 } //1
		$a_01_2 = {67 65 74 4d 65 73 73 61 67 65 73 46 72 6f 6d 49 6e 74 65 6e 74 } //1 getMessagesFromIntent
		$a_01_3 = {67 65 74 44 69 73 70 6c 61 79 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getDisplayMessageBody
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}