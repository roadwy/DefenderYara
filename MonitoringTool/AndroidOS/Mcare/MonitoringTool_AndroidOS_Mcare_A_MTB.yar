
rule MonitoringTool_AndroidOS_Mcare_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Mcare.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 53 69 6d 43 68 61 6e 67 65 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //01 00  sendSimChangeNotification
		$a_00_1 = {2f 72 70 63 2f 6e 6f 74 69 66 79 57 69 70 65 6f 75 74 } //01 00  /rpc/notifyWipeout
		$a_00_2 = {72 65 71 75 65 73 74 4c 6f 63 61 74 69 6f 6e 49 6e 66 6f } //01 00  requestLocationInfo
		$a_00_3 = {72 65 74 72 69 65 76 65 41 70 70 4c 69 73 74 } //01 00  retrieveAppList
		$a_00_4 = {2f 62 61 63 6b 75 70 2f 73 65 6e 64 43 61 6c 6c 4c 6f 67 } //01 00  /backup/sendCallLog
		$a_00_5 = {73 65 6e 64 53 63 72 65 65 6e 4c 6f 63 6b 52 65 73 75 6c 74 } //01 00  sendScreenLockResult
		$a_00_6 = {6d 6f 62 69 75 63 61 72 65 } //05 00  mobiucare
		$a_00_7 = {63 6f 6d 2e 6d 6f 62 69 75 63 61 72 65 2e 63 6c 69 65 6e 74 } //00 00  com.mobiucare.client
	condition:
		any of ($a_*)
 
}