
rule MonitoringTool_AndroidOS_Folme_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Folme.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 66 6d 65 65 2f 66 6d 65 65 73 65 72 76 } //01 00  Lcom/fmee/fmeeserv
		$a_01_1 = {2f 66 6d 65 65 73 65 72 76 5f 73 74 65 61 6c 74 68 2e 61 70 6b } //01 00  /fmeeserv_stealth.apk
		$a_01_2 = {52 6f 75 74 65 4d 6f 6e 69 74 6f 72 } //01 00  RouteMonitor
		$a_01_3 = {4f 75 74 67 6f 69 6e 67 43 61 6c 6c 52 65 63 65 69 76 65 72 } //00 00  OutgoingCallReceiver
	condition:
		any of ($a_*)
 
}