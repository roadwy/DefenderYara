
rule TrojanSpy_AndroidOS_SAgnt_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 46 69 6c 65 44 65 74 61 69 6c 65 64 } //1 sendFileDetailed
		$a_00_1 = {73 65 6e 74 54 6f 73 76 65 72 } //1 sentTosver
		$a_00_2 = {73 65 6e 64 43 6f 6e 74 61 63 74 73 44 65 74 61 69 6c 73 } //1 sendContactsDetails
		$a_00_3 = {2f 2f 63 61 6c 6c 5f 6c 6f 67 2f 63 61 6c 6c 73 } //1 //call_log/calls
		$a_00_4 = {73 65 6e 64 47 45 54 } //1 sendGET
		$a_00_5 = {73 65 6e 64 4d 79 53 74 75 66 66 44 65 74 61 69 6c 65 64 } //1 sendMyStuffDetailed
		$a_00_6 = {73 74 6f 72 65 47 50 53 } //1 storeGPS
		$a_00_7 = {73 65 6e 74 4d 69 63 52 65 63 6f 72 64 69 6e 67 } //1 sentMicRecording
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=7
 
}