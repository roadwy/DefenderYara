
rule MonitoringTool_AndroidOS_Soundy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Soundy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 6c 6b 4c 69 73 74 } //1 stalkList
		$a_01_1 = {4f 75 74 47 6f 69 6e 67 4e 75 6d 44 65 74 65 63 74 6f 72 } //1 OutGoingNumDetector
		$a_00_2 = {63 6f 6d 2e 6b 66 68 64 68 61 2e 66 6b 6a 66 67 6a 64 69 } //1 com.kfhdha.fkjfgjdi
		$a_01_3 = {53 61 76 65 50 68 6f 74 6f 54 61 73 6b } //1 SavePhotoTask
		$a_01_4 = {53 63 72 65 65 6e 4c 69 76 65 41 63 74 69 76 69 74 79 } //1 ScreenLiveActivity
		$a_00_5 = {73 79 73 74 65 6d 2f 62 69 6e 2f 63 68 6d 6f 64 20 37 34 34 20 63 61 70 74 75 72 65 73 63 72 } //1 system/bin/chmod 744 capturescr
		$a_01_6 = {53 4d 53 4f 62 73 65 72 76 65 72 } //1 SMSObserver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}