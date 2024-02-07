
rule Trojan_AndroidOS_SkeeyahSpy_Y{
	meta:
		description = "Trojan:AndroidOS/SkeeyahSpy.Y,SIGNATURE_TYPE_DEXHSTR_EXT,2d 00 2d 00 10 00 00 0a 00 "
		
	strings :
		$a_00_0 = {75 70 6c 6f 61 64 63 61 6c 6c 73 72 65 63 6f 72 64 } //0a 00  uploadcallsrecord
		$a_00_1 = {75 70 6c 6f 61 64 43 61 6c 6c 52 65 63 6f 72 64 69 6e 67 73 } //0a 00  uploadCallRecordings
		$a_00_2 = {75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 } //0a 00  uploadContact
		$a_00_3 = {63 6f 6e 74 61 63 74 73 75 70 6c 6f 61 64 } //0a 00  contactsupload
		$a_00_4 = {75 70 6c 6f 61 64 53 6d 73 } //0a 00  uploadSms
		$a_00_5 = {73 6d 73 75 70 6c 6f 61 64 } //0a 00  smsupload
		$a_00_6 = {73 65 74 4b 65 79 6c 6f 67 73 } //0a 00  setKeylogs
		$a_00_7 = {67 65 74 4b 65 79 4c 6f 67 73 } //01 00  getKeyLogs
		$a_00_8 = {75 70 6c 6f 61 64 43 61 6c 6c 4c 6f 67 } //01 00  uploadCallLog
		$a_00_9 = {67 65 74 69 6e 73 74 69 61 6c 6c 64 61 70 70 73 6c 69 73 74 } //01 00  getinstialldappslist
		$a_00_10 = {65 6e 76 6f 69 72 6d 65 6e 74 41 75 64 69 6f 73 } //01 00  envoirmentAudios
		$a_00_11 = {75 70 6c 6f 61 64 41 75 64 69 6f } //01 00  uploadAudio
		$a_00_12 = {66 6e 5f 67 65 74 43 61 6d 65 72 61 } //01 00  fn_getCamera
		$a_00_13 = {66 6e 5f 67 65 74 6c 6f 63 61 74 69 6f 6e } //01 00  fn_getlocation
		$a_00_14 = {75 70 6c 6f 61 64 4c 69 73 74 50 61 74 68 } //01 00  uploadListPath
		$a_00_15 = {64 65 6c 65 74 65 5f 70 61 73 73 5f 64 61 74 65 } //00 00  delete_pass_date
		$a_00_16 = {5d 04 00 00 ea 38 05 80 5c 28 00 00 eb 38 05 80 00 00 01 00 08 00 12 00 af 01 53 70 79 4e 6f 6f 6e 2e 54 54 55 46 21 4d 54 42 00 } //00 01 
	condition:
		any of ($a_*)
 
}