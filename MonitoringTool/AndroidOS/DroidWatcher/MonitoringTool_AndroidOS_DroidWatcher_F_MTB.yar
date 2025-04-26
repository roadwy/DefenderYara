
rule MonitoringTool_AndroidOS_DroidWatcher_F_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/DroidWatcher.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 65 6c 65 74 65 43 61 6c 6c 4c 6f 67 } //1 DeleteCallLog
		$a_01_1 = {48 69 64 64 65 6e 43 61 6d } //1 HiddenCam
		$a_01_2 = {73 74 61 72 74 52 65 63 6f 72 64 43 41 4c 4c } //1 startRecordCALL
		$a_01_3 = {67 65 74 42 72 6f 77 73 65 72 48 69 73 74 6f 72 79 } //1 getBrowserHistory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}