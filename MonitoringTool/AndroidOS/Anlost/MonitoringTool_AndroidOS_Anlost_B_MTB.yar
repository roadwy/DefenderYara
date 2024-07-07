
rule MonitoringTool_AndroidOS_Anlost_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Anlost.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 79 73 74 65 6d 20 61 70 70 20 72 65 6d 6f 76 61 6c 20 73 75 63 63 65 73 73 21 } //1 System app removal success!
		$a_00_1 = {61 6e 64 72 6f 69 64 6c 6f 73 74 } //1 androidlost
		$a_00_2 = {4c 65 74 20 75 73 20 68 6f 70 65 20 79 6f 75 20 64 69 64 20 6e 6f 74 20 6d 65 73 73 20 73 6f 6d 65 74 68 69 6e 67 20 75 70 } //1 Let us hope you did not mess something up
		$a_00_3 = {62 61 63 6b 75 70 73 6d 73 } //1 backupsms
		$a_00_4 = {53 4d 53 20 65 72 61 73 65 20 53 44 20 63 61 72 64 } //1 SMS erase SD card
		$a_00_5 = {57 69 70 65 20 70 68 6f 6e 65 } //1 Wipe phone
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}