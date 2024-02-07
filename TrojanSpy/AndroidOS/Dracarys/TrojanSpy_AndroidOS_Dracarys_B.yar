
rule TrojanSpy_AndroidOS_Dracarys_B{
	meta:
		description = "TrojanSpy:AndroidOS/Dracarys.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 75 64 69 6f 52 65 63 6f 72 64 69 6e 67 55 70 6c 6f 61 64 } //01 00  AudioRecordingUpload
		$a_00_1 = {44 72 61 63 61 72 79 73 52 65 63 65 69 76 65 72 } //01 00  DracarysReceiver
		$a_00_2 = {2e 77 6e 6b 5f 72 65 63 } //01 00  .wnk_rec
		$a_00_3 = {25 73 2f 25 73 2f 72 65 70 6f 72 74 2f 63 6f 6e 74 61 63 74 73 } //01 00  %s/%s/report/contacts
		$a_00_4 = {2e 61 75 64 69 6f 5f 6d 6f 6e } //01 00  .audio_mon
		$a_00_5 = {43 61 6c 6c 4c 6f 67 52 65 70 6f 72 74 57 6f 72 6b 65 72 } //01 00  CallLogReportWorker
		$a_00_6 = {53 59 4e 43 5f 50 52 49 56 41 54 45 5f 46 49 4c 45 53 5f 55 52 4c } //01 00  SYNC_PRIVATE_FILES_URL
		$a_00_7 = {52 45 51 55 45 53 54 5f 48 45 41 52 54 42 45 41 54 5f 55 52 4c } //01 00  REQUEST_HEARTBEAT_URL
		$a_00_8 = {41 70 70 49 6e 66 6f 47 61 74 68 65 72 65 72 } //00 00  AppInfoGatherer
	condition:
		any of ($a_*)
 
}