
rule MonitoringTool_AndroidOS_Lynep_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Lynep.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {74 72 61 63 6b 5f 70 68 6f 6e 75 6d 62 65 72 } //1 track_phonumber
		$a_00_1 = {61 70 70 73 2f 61 70 70 73 64 61 74 61 2e 70 68 70 } //1 apps/appsdata.php
		$a_00_2 = {6c 61 73 74 63 68 65 63 6b 61 6c } //1 lastcheckal
		$a_00_3 = {6e 65 65 64 53 65 6e 64 54 6f 54 72 61 63 6b 41 70 70 } //1 needSendToTrackApp
		$a_01_4 = {74 72 61 63 6b 61 70 70 64 61 74 61 } //1 trackappdata
		$a_00_5 = {73 65 6e 64 5f 64 65 76 69 63 65 5f 64 61 74 61 } //1 send_device_data
		$a_00_6 = {2f 73 74 61 74 73 2e 70 68 70 } //1 /stats.php
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}