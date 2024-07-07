
rule TrojanSpy_AndroidOS_RatMilad_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RatMilad.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 43 61 6c 6c 4c 6f 67 73 } //1 sendCallLogs
		$a_01_1 = {74 65 78 74 6d 65 2e 6e 65 74 77 6f 72 6b } //1 textme.network
		$a_01_2 = {63 6f 6e 74 61 63 74 4c 69 73 74 } //1 contactList
		$a_01_3 = {73 65 6e 64 47 50 53 54 6f 53 65 72 76 65 72 } //1 sendGPSToServer
		$a_01_4 = {53 6f 75 6e 64 52 65 63 6f 72 64 65 72 } //1 SoundRecorder
		$a_01_5 = {73 65 6e 64 53 4d 53 4c 69 73 74 } //1 sendSMSList
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}