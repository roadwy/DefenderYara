
rule MonitoringTool_AndroidOS_Dnotua_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Dnotua.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 6f 67 5f 63 68 65 63 6b 65 72 2e 74 78 74 } //01 00  log_checker.txt
		$a_01_1 = {53 74 61 72 74 4c 6f 67 46 69 6c 65 } //01 00  StartLogFile
		$a_01_2 = {4c 63 6f 6d 2f 6d 6f 6e 69 74 6f 72 63 68 65 63 6b 65 72 2f 4d 6f 6e 69 74 6f 72 43 68 65 63 6b 65 72 } //01 00  Lcom/monitorchecker/MonitorChecker
		$a_01_3 = {43 68 65 63 6b 41 6e 72 6f 69 64 4d 6f 6e 69 74 6f 72 } //00 00  CheckAnroidMonitor
	condition:
		any of ($a_*)
 
}