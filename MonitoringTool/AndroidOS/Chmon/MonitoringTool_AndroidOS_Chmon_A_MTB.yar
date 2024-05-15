
rule MonitoringTool_AndroidOS_Chmon_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Chmon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 6a 6c 7a 62 2f 61 6e 64 72 6f 69 64 2f 54 75 72 6e 41 63 74 69 76 69 74 79 } //01 00  Lcom/jlzb/android/TurnActivity
		$a_00_1 = {53 6d 73 53 65 6e 64 43 6f 6e 74 65 6e 74 57 61 74 63 68 65 72 } //01 00  SmsSendContentWatcher
		$a_00_2 = {50 68 6f 6e 65 49 73 4f 6e 4c 69 6e 65 53 65 72 76 69 63 65 } //01 00  PhoneIsOnLineService
		$a_00_3 = {48 69 64 64 65 6e 4f 70 65 6e 41 70 70 53 65 72 76 69 63 65 } //01 00  HiddenOpenAppService
		$a_00_4 = {55 70 6c 6f 61 64 4f 66 74 65 6e 47 6f 50 6c 61 63 65 53 65 72 76 69 63 65 } //00 00  UploadOftenGoPlaceService
	condition:
		any of ($a_*)
 
}