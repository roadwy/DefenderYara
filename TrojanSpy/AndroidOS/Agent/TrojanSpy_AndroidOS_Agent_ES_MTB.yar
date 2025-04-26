
rule TrojanSpy_AndroidOS_Agent_ES_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Agent.ES!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {61 70 70 2e 6c 69 74 65 2e 62 6f 74 } //1 app.lite.bot
		$a_00_1 = {53 63 72 65 65 6e 52 65 63 6f 72 64 65 72 53 65 72 76 69 63 65 } //1 ScreenRecorderService
		$a_00_2 = {2f 6b 65 79 6c 6f 67 67 65 72 2e 74 78 74 } //1 /keylogger.txt
		$a_00_3 = {2f 75 70 6c 6f 61 64 65 64 5f 66 69 6c 65 73 2e 74 78 74 } //1 /uploaded_files.txt
		$a_00_4 = {2f 66 65 74 63 68 65 64 5f 66 69 6c 65 5f 70 61 74 68 2e 74 78 74 } //1 /fetched_file_path.txt
		$a_00_5 = {2f 64 65 6c 5f 72 65 63 6f 72 64 } //1 /del_record
		$a_00_6 = {2f 70 72 6f 63 2f 6d 65 6d 69 6e 66 6f } //1 /proc/meminfo
		$a_00_7 = {4c 61 70 70 2f 6c 69 74 65 2f 62 6f 74 2f 61 63 74 69 76 69 74 69 65 73 2f 4c 6f 63 6b 4d 65 4e 6f 77 41 63 74 69 76 69 74 79 } //1 Lapp/lite/bot/activities/LockMeNowActivity
		$a_00_8 = {53 45 54 54 49 4e 47 5f 55 50 4c 4f 41 44 5f 55 53 49 4e 47 5f 4d 4f 42 49 4c 45 5f 44 41 54 41 } //1 SETTING_UPLOAD_USING_MOBILE_DATA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=7
 
}