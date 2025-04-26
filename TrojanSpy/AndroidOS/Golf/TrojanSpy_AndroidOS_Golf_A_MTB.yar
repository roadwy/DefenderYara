
rule TrojanSpy_AndroidOS_Golf_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Golf.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {5f 65 63 61 70 33 32 78 } //1 _ecap32x
		$a_00_1 = {67 65 74 52 75 6e 6e 69 6e 67 41 70 70 50 72 6f 63 65 73 73 65 73 } //1 getRunningAppProcesses
		$a_00_2 = {5f 76 6f 69 63 65 52 65 63 6f 72 64 20 67 6f 69 6e 67 20 74 6f 20 61 75 64 69 6f 52 65 63 6f 72 64 65 72 2e 73 74 61 72 74 56 6f 69 63 65 52 65 63 6f 72 64 65 72 28 29 } //1 _voiceRecord going to audioRecorder.startVoiceRecorder()
		$a_00_3 = {4d 61 69 6e 20 73 65 72 76 69 63 65 20 6e 6f 74 20 72 75 6e 6e 69 6e 67 20 67 6f 69 6e 67 20 74 6f 20 73 74 61 72 74 20 69 74 2e 2e 2e } //1 Main service not running going to start it...
		$a_00_4 = {44 6f 67 20 69 73 20 73 65 74 20 66 6f 72 20 61 63 74 69 6f 6e } //1 Dog is set for action
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}