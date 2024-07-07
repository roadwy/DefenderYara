
rule Trojan_AndroidOS_Banker_A{
	meta:
		description = "Trojan:AndroidOS/Banker.A,SIGNATURE_TYPE_DEXHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {91 02 05 04 23 20 9f 06 12 01 91 02 05 04 35 21 0f 00 62 02 b5 00 90 03 04 01 4a 02 02 03 b7 62 8e 22 50 02 00 01 d8 01 01 01 28 f0 } //10
		$a_01_1 = {6c 6f 61 64 44 61 74 61 57 69 74 68 42 61 73 65 55 52 4c } //1 loadDataWithBaseURL
		$a_01_2 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getMessageBody
		$a_01_3 = {73 65 6e 64 54 65 78 74 4d 65 73 73 61 67 65 } //1 sendTextMessage
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}