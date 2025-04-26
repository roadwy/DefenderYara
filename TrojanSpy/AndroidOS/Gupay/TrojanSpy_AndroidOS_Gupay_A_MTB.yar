
rule TrojanSpy_AndroidOS_Gupay_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Gupay.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 41 6e 64 53 65 6e 64 44 61 74 61 } //1 getAndSendData
		$a_01_1 = {73 65 6e 64 50 61 79 44 61 74 61 } //1 sendPayData
		$a_01_2 = {64 65 6c 65 74 65 41 50 50 } //1 deleteAPP
		$a_01_3 = {69 73 50 68 6f 6e 65 43 61 6c 6c 69 6e 67 } //1 isPhoneCalling
		$a_01_4 = {77 61 73 53 63 72 65 65 6e 4f 6e } //1 wasScreenOn
		$a_01_5 = {73 65 6e 64 50 6f 73 74 52 65 71 75 65 73 74 } //1 sendPostRequest
		$a_01_6 = {6d 53 70 59 } //5 mSpY
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*5) >=9
 
}