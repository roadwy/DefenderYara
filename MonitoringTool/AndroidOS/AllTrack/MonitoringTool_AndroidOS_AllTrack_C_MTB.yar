
rule MonitoringTool_AndroidOS_AllTrack_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/AllTrack.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 43 4b 45 54 5f 53 45 43 52 45 54 } //05 00  SOCKET_SECRET
		$a_01_1 = {4c 63 69 74 79 2f 72 75 73 73 2f 61 6c 6c 74 72 61 63 6b 65 72 63 6f 72 70 2f 53 74 61 72 74 41 63 74 69 76 69 74 79 } //01 00  Lcity/russ/alltrackercorp/StartActivity
		$a_01_2 = {41 63 74 69 6f 6e 47 65 74 42 72 6f 77 73 65 72 48 69 73 74 6f 72 79 } //01 00  ActionGetBrowserHistory
		$a_01_3 = {41 63 74 69 6f 6e 47 65 74 53 4d 53 } //01 00  ActionGetSMS
		$a_01_4 = {46 75 73 65 64 4c 6f 63 61 74 69 6f 6e 52 65 63 65 69 76 65 72 } //05 00  FusedLocationReceiver
		$a_01_5 = {63 69 74 79 2e 72 75 73 73 2e 43 48 45 43 4b 5f 4c 41 53 54 5f 45 4e 54 52 59 } //00 00  city.russ.CHECK_LAST_ENTRY
	condition:
		any of ($a_*)
 
}