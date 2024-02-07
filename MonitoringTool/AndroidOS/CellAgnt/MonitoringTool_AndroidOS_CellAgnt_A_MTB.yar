
rule MonitoringTool_AndroidOS_CellAgnt_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/CellAgnt.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 4c 6f 67 4f 62 73 65 72 76 65 72 } //01 00  CallLogObserver
		$a_01_1 = {64 65 6c 65 74 65 43 61 6c 6c 4c 6f 67 } //01 00  deleteCallLog
		$a_00_2 = {63 6f 6d 2e 69 74 68 65 69 6d 61 2e 6b 69 6c 6c 61 6c 6c } //01 00  com.itheima.killall
		$a_01_3 = {41 70 70 6c 6f 63 6b 4f 62 73 65 72 76 65 72 } //01 00  ApplockObserver
		$a_01_4 = {4c 6f 73 74 46 69 6e 64 41 63 74 69 76 69 74 79 } //01 00  LostFindActivity
		$a_01_5 = {6b 69 6c 6c 65 64 54 61 73 6b 49 6e 66 6f 73 } //01 00  killedTaskInfos
		$a_01_6 = {77 69 70 65 44 61 74 61 } //00 00  wipeData
	condition:
		any of ($a_*)
 
}