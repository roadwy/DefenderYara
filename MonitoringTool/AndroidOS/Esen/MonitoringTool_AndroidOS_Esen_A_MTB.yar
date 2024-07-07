
rule MonitoringTool_AndroidOS_Esen_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Esen.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 61 76 65 64 53 65 6e 64 69 6e 67 4d 73 67 20 } //1 SavedSendingMsg 
		$a_00_1 = {64 6f 53 63 72 65 65 6e 43 61 70 74 75 72 65 } //1 doScreenCapture
		$a_00_2 = {6c 6f 63 62 61 63 6b 75 70 69 6e 66 6f } //1 locbackupinfo
		$a_00_3 = {73 65 6e 64 43 61 6c 6c 4c 6f 67 } //1 sendCallLog
		$a_00_4 = {73 65 6e 64 4c 6f 63 61 74 69 6f 6e 49 6e 66 6f } //1 sendLocationInfo
		$a_00_5 = {2f 70 61 5f 69 6e 73 65 72 74 63 61 6c 6c 6c 6f 67 2e 70 68 70 } //1 /pa_insertcalllog.php
		$a_00_6 = {63 6f 6d 2e 65 73 65 6e 2e 66 79 74 74 61 72 67 65 74 32 } //1 com.esen.fyttarget2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}