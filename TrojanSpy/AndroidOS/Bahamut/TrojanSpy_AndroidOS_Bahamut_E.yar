
rule TrojanSpy_AndroidOS_Bahamut_E{
	meta:
		description = "TrojanSpy:AndroidOS/Bahamut.E,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 53 47 5f 54 52 49 47 5f 41 4c 41 52 4d 5f 48 45 41 52 54 42 45 41 54 } //01 00  MSG_TRIG_ALARM_HEARTBEAT
		$a_00_1 = {4e 65 74 77 6f 72 6b 53 74 61 74 75 73 53 65 72 76 69 63 65 24 } //01 00  NetworkStatusService$
		$a_00_2 = {4d 53 47 5f 43 4f 4e 4e 45 43 54 49 56 49 54 59 } //01 00  MSG_CONNECTIVITY
		$a_00_3 = {64 6a 64 65 65 75 24 74 75 79 67 6c 6e } //01 00  djdeeu$tuygln
		$a_00_4 = {77 61 74 65 72 2e 7a 69 70 } //00 00  water.zip
	condition:
		any of ($a_*)
 
}