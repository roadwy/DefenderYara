
rule MonitoringTool_AndroidOS_Trackme_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Trackme.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 74 72 61 63 6b 69 6e 67 5f 73 6d 61 72 74 70 68 6f 6e } //1 com.tracking_smartphon
		$a_00_1 = {74 72 61 63 6b 69 6e 67 73 6d 61 72 74 70 68 6f 6e 65 2e 63 6f 6d } //1 trackingsmartphone.com
		$a_00_2 = {43 65 6c 6c 54 72 61 63 6b 65 72 } //1 CellTracker
		$a_00_3 = {65 78 65 63 75 74 65 73 6d 73 63 6f 6d 6d 61 6e 64 73 } //1 executesmscommands
		$a_00_4 = {63 61 6c 6c 61 6e 64 73 6d 73 6c 6f 67 73 } //1 callandsmslogs
		$a_00_5 = {75 72 6c 68 69 73 74 6f 72 79 } //1 urlhistory
		$a_00_6 = {77 69 70 65 6f 75 74 } //1 wipeout
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}