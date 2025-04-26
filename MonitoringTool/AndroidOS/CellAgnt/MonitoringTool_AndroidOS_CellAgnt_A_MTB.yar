
rule MonitoringTool_AndroidOS_CellAgnt_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/CellAgnt.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 4c 6f 67 4f 62 73 65 72 76 65 72 } //1 CallLogObserver
		$a_01_1 = {64 65 6c 65 74 65 43 61 6c 6c 4c 6f 67 } //1 deleteCallLog
		$a_00_2 = {63 6f 6d 2e 69 74 68 65 69 6d 61 2e 6b 69 6c 6c 61 6c 6c } //1 com.itheima.killall
		$a_01_3 = {41 70 70 6c 6f 63 6b 4f 62 73 65 72 76 65 72 } //1 ApplockObserver
		$a_01_4 = {4c 6f 73 74 46 69 6e 64 41 63 74 69 76 69 74 79 } //1 LostFindActivity
		$a_01_5 = {6b 69 6c 6c 65 64 54 61 73 6b 49 6e 66 6f 73 } //1 killedTaskInfos
		$a_01_6 = {77 69 70 65 44 61 74 61 } //1 wipeData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}