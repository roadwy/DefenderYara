
rule MonitoringTool_AndroidOS_Ikeymon_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Ikeymon.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 48 69 73 74 6f 72 79 5f 44 65 6c 65 74 65 2e 74 78 74 } //1 CallHistory_Delete.txt
		$a_00_1 = {4f 75 74 67 6f 69 6e 67 43 61 6c 6c 4f 62 73 65 72 76 65 72 } //1 OutgoingCallObserver
		$a_00_2 = {43 61 6c 6c 41 75 64 69 6f 52 65 63 6f 72 64 } //1 CallAudioRecord
		$a_00_3 = {47 65 74 41 6c 6c 56 6f 69 63 65 49 6e 66 6f 5f 66 61 63 65 62 6f 6f 6b } //1 GetAllVoiceInfo_facebook
		$a_00_4 = {43 68 72 6f 6d 65 4c 6f 67 67 69 6e 67 } //1 ChromeLogging
		$a_00_5 = {42 65 67 69 6e 5f 53 63 72 65 65 6e 73 68 6f 74 } //1 Begin_Screenshot
		$a_00_6 = {43 68 72 6f 6d 65 5f 57 65 62 48 69 73 74 72 } //1 Chrome_WebHistr
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}