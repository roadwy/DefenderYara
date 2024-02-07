
rule Trojan_AndroidOS_Fakecalls_F{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.F,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 45 51 55 45 53 54 5f 55 50 4c 4f 41 44 5f 49 4e 46 4f 5f 46 49 4c 45 } //02 00  REQUEST_UPLOAD_INFO_FILE
		$a_01_1 = {65 76 65 6e 74 5f 72 65 63 6f 72 64 69 6e 67 5f 66 72 6f 6d 5f 73 65 72 76 65 72 } //02 00  event_recording_from_server
		$a_01_2 = {53 4f 43 4b 45 54 5f 45 56 45 4e 54 5f 53 45 4e 44 5f 43 41 4c 4c 5f 53 54 41 52 54 45 44 5f 4d 53 47 5f 54 4f 5f 53 45 52 56 45 52 } //02 00  SOCKET_EVENT_SEND_CALL_STARTED_MSG_TO_SERVER
		$a_01_3 = {53 43 41 4e 4e 49 4e 47 5f 41 4c 4c 5f 41 50 50 } //00 00  SCANNING_ALL_APP
	condition:
		any of ($a_*)
 
}