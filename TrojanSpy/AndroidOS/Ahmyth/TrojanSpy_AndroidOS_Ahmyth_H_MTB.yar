
rule TrojanSpy_AndroidOS_Ahmyth_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Ahmyth.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 74 65 63 68 65 78 70 65 72 74 2f 73 69 67 6e 61 6c 6c 69 74 65 } //1 Lcom/techexpert/signallite
		$a_00_1 = {33 2e 74 63 70 2e 6e 67 72 6f 6b 2e 69 6f } //1 3.tcp.ngrok.io
		$a_00_2 = {67 65 74 43 61 6c 6c 4c 6f 67 73 } //1 getCallLogs
		$a_00_3 = {67 65 74 43 6f 6e 74 61 63 74 } //1 getContact
		$a_00_4 = {73 74 61 72 74 52 65 63 6f 72 64 69 6e 67 } //1 startRecording
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}