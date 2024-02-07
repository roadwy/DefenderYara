
rule TrojanSpy_AndroidOS_Bahamut_I{
	meta:
		description = "TrojanSpy:AndroidOS/Bahamut.I,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 61 63 74 46 65 74 63 68 69 6e 67 53 65 72 76 69 63 65 } //01 00  ContactFetchingService
		$a_00_1 = {69 6e 64 65 78 5f 73 6d 73 5f 5f 69 64 } //01 00  index_sms__id
		$a_01_2 = {43 61 6c 6c 4c 6f 67 46 65 74 63 68 53 65 72 76 69 63 65 } //01 00  CallLogFetchService
		$a_00_3 = {69 6e 64 65 78 5f 63 61 6c 6c 5f 6c 6f 67 73 5f 63 61 6c 6c 5f 69 64 } //01 00  index_call_logs_call_id
		$a_00_4 = {5f 63 6f 6e 74 61 63 74 73 5f 75 73 65 72 5f 70 68 6f 6e 65 } //01 00  _contacts_user_phone
		$a_00_5 = {69 6e 64 65 78 5f 66 69 6c 65 73 5f 64 61 74 61 5f 66 69 6c 65 5f 70 61 74 68 } //01 00  index_files_data_file_path
		$a_01_6 = {53 6d 73 46 65 74 63 68 53 65 72 76 69 63 65 } //01 00  SmsFetchService
		$a_00_7 = {69 6e 64 65 78 5f 75 73 65 72 5f 6c 6f 63 61 74 69 6f 6e 5f 61 64 64 72 65 73 73 } //01 00  index_user_location_address
		$a_00_8 = {74 78 74 5f 76 69 64 65 6f 5f 75 73 65 72 5f 6e 61 6d 65 } //01 00  txt_video_user_name
		$a_01_9 = {75 73 65 72 53 6d 73 44 61 6f } //00 00  userSmsDao
	condition:
		any of ($a_*)
 
}