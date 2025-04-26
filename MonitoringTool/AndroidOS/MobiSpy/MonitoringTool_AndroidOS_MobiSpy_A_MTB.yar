
rule MonitoringTool_AndroidOS_MobiSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MobiSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 70 73 61 63 2f 61 2f 70 72 6f 63 65 73 73 73 65 72 76 69 63 65 } //1 Lcom/psac/a/processservice
		$a_01_1 = {32 61 75 64 69 6f 75 70 6c 6f 61 64 66 69 6c 65 73 } //1 2audiouploadfiles
		$a_01_2 = {64 75 6d 70 57 69 66 69 } //1 dumpWifi
		$a_01_3 = {73 61 76 65 43 65 6c 6c 44 65 74 61 69 6c 73 } //1 saveCellDetails
		$a_01_4 = {75 70 6c 6f 61 64 5f 63 6f 75 6e 74 5f 6d 65 64 69 61 } //1 upload_count_media
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}