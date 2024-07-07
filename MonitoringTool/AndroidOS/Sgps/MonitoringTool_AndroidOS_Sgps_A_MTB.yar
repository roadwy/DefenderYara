
rule MonitoringTool_AndroidOS_Sgps_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Sgps.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,13 00 13 00 08 00 00 "
		
	strings :
		$a_01_0 = {48 69 64 64 65 6e 55 70 6c 6f 61 64 } //1 HiddenUpload
		$a_01_1 = {44 65 76 69 63 65 49 6e 66 6f 41 73 79 6e 63 54 61 73 6b } //1 DeviceInfoAsyncTask
		$a_01_2 = {59 6f 75 72 41 73 79 6e 63 54 61 73 6b 5f 50 68 6f 6e 65 57 69 70 65 } //1 YourAsyncTask_PhoneWipe
		$a_01_3 = {67 65 74 53 4d 53 44 65 74 61 69 6c } //1 getSMSDetail
		$a_01_4 = {53 70 79 43 61 6c 6c } //5 SpyCall
		$a_01_5 = {73 61 76 65 42 52 4f 57 53 45 52 5f 50 72 65 43 6f 75 6e 74 } //1 saveBROWSER_PreCount
		$a_01_6 = {73 6d 73 67 70 73 70 79 } //5 smsgpspy
		$a_01_7 = {6d 61 69 6e 5f 73 70 79 } //5 main_spy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5+(#a_01_5  & 1)*1+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5) >=19
 
}