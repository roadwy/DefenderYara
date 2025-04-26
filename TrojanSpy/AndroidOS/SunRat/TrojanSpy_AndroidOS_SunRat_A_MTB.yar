
rule TrojanSpy_AndroidOS_SunRat_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SunRat.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {64 61 74 61 53 6e 61 70 73 68 6f 74 } //1 dataSnapshot
		$a_00_1 = {63 68 61 74 41 6e 64 53 70 79 } //1 chatAndSpy
		$a_00_2 = {55 70 6c 6f 61 64 50 6f 73 74 54 61 73 6b } //1 UploadPostTask
		$a_00_3 = {74 74 70 3a 2f 2f 63 68 61 74 6a 2e 67 6f 6c 64 65 6e 62 69 72 64 63 6f 69 6e 2e 63 6f 6d } //1 ttp://chatj.goldenbirdcoin.com
		$a_00_4 = {4d 6f 6e 69 74 6f 72 69 6e 67 54 69 6d 65 72 54 61 73 6b } //1 MonitoringTimerTask
		$a_00_5 = {75 70 6c 6f 61 64 41 75 64 69 6f 46 69 6c 65 } //1 uploadAudioFile
		$a_00_6 = {73 61 76 65 41 75 64 69 6f 4f 6e 52 6f 6f 74 53 74 6f 72 61 67 65 } //1 saveAudioOnRootStorage
		$a_00_7 = {53 61 76 65 57 68 61 74 73 70 56 6f 69 63 65 4e 6f 74 65 73 } //1 SaveWhatspVoiceNotes
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=7
 
}