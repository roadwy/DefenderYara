
rule MonitoringTool_AndroidOS_Ikeymon_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Ikeymon.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6b 65 79 4c 6f 67 67 65 72 6c 6f 67 73 } //1 keyLoggerlogs
		$a_01_1 = {63 61 6c 6c 68 69 73 74 6f 72 79 } //1 callhistory
		$a_01_2 = {50 72 65 66 73 5f 41 70 70 42 6c 6f 63 6b 65 72 41 63 74 69 76 69 74 79 } //1 Prefs_AppBlockerActivity
		$a_01_3 = {43 61 6c 6c 69 6e 67 52 65 63 6f 72 64 5f 53 65 72 76 69 63 65 } //1 CallingRecord_Service
		$a_01_4 = {2f 64 61 74 61 2f 63 6f 6d 2e 61 73 2e 6d 6f 6e 69 74 6f 72 69 6e 67 61 70 70 } //1 /data/com.as.monitoringapp
		$a_01_5 = {62 6b 5f 72 65 61 64 4c 6f 67 73 2e 74 78 74 } //1 bk_readLogs.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}