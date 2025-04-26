
rule MonitoringTool_AndroidOS_Alltracker_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Alltracker.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {4c 63 69 74 79 2f 72 75 73 73 2f 61 6c 6c 74 72 61 63 6b 65 72 63 6f 72 70 } //5 Lcity/russ/alltrackercorp
		$a_01_1 = {4c 6f 63 61 74 69 6f 6e 4c 6f 67 67 65 72 53 65 72 76 69 63 65 } //1 LocationLoggerService
		$a_01_2 = {68 69 73 74 6f 72 79 5f 63 61 6c 6c 73 } //1 history_calls
		$a_01_3 = {43 6f 6c 6c 65 63 74 50 68 6f 74 6f 73 53 65 72 76 69 63 65 } //1 CollectPhotosService
		$a_01_4 = {55 70 6c 6f 61 64 53 63 72 65 65 6e 4f 6e 50 68 6f 74 6f 73 } //1 UploadScreenOnPhotos
		$a_01_5 = {4d 6f 6e 69 74 6f 72 65 64 41 63 74 69 76 69 74 79 } //1 MonitoredActivity
		$a_01_6 = {63 69 74 79 2f 72 75 73 73 2f 61 6c 6c 74 72 61 63 6b 65 72 66 61 6d 69 6c 79 } //5 city/russ/alltrackerfamily
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*5) >=8
 
}