
rule MonitoringTool_AndroidOS_DroidWatcher_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/DroidWatcher.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 74 65 6c 65 67 72 75 73 2f 53 65 72 76 65 72 4d 65 73 73 61 6e 67 65 72 } //1 com/telegrus/ServerMessanger
		$a_01_1 = {73 74 61 72 74 52 65 63 6f 72 64 43 41 4c 4c } //1 startRecordCALL
		$a_01_2 = {63 6f 70 79 53 4d 53 54 6f 44 57 44 42 } //1 copySMSToDWDB
		$a_01_3 = {67 65 74 42 72 6f 77 73 65 72 48 69 73 74 6f 72 79 } //1 getBrowserHistory
		$a_01_4 = {61 64 64 43 6c 69 62 6f 61 72 64 } //1 addCliboard
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}