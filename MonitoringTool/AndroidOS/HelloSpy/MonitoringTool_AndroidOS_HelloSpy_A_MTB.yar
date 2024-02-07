
rule MonitoringTool_AndroidOS_HelloSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/HelloSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 65 6c 6c 6f 53 70 79 } //01 00  HelloSpy
		$a_00_1 = {66 6c 75 73 68 64 62 64 2e 6d 61 78 78 73 70 79 2e 63 6f 6d } //01 00  flushdbd.maxxspy.com
		$a_00_2 = {52 65 6d 6f 74 65 41 63 63 65 73 73 43 6d 64 } //01 00  RemoteAccessCmd
		$a_00_3 = {52 65 63 6f 72 64 43 61 6c 6c 53 65 72 76 69 63 65 } //01 00  RecordCallService
		$a_00_4 = {53 65 6e 64 44 61 74 61 4d 61 6e 61 67 65 72 46 6f 72 57 68 61 74 73 61 70 70 } //01 00  SendDataManagerForWhatsapp
		$a_00_5 = {43 6f 6e 74 65 6e 74 4f 62 73 65 72 76 65 72 46 6f 72 53 6d 73 } //00 00  ContentObserverForSms
	condition:
		any of ($a_*)
 
}