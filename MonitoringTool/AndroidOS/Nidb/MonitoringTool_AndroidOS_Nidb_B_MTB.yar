
rule MonitoringTool_AndroidOS_Nidb_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Nidb.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 65 74 48 69 64 65 41 44 65 76 69 63 65 } //1 setHideADevice
		$a_00_1 = {61 70 70 73 70 79 2e 6e 65 74 2f 63 70 2f 73 65 72 76 65 72 } //1 appspy.net/cp/server
		$a_00_2 = {41 43 61 6c 6c 57 61 74 63 68 65 72 } //1 ACallWatcher
		$a_00_3 = {67 65 74 53 4d 53 48 69 73 74 6f 72 79 } //1 getSMSHistory
		$a_00_4 = {41 54 72 61 63 6b 65 72 57 61 74 63 68 65 72 } //1 ATrackerWatcher
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}