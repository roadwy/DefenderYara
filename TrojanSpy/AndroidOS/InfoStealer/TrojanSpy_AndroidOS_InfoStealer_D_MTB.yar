
rule TrojanSpy_AndroidOS_InfoStealer_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 75 70 6c 6f 61 64 2f 73 6e 61 70 73 68 6f 74 75 70 6c 6f 61 64 2e 73 68 74 6d 6c } //01 00  /upload/snapshotupload.shtml
		$a_00_1 = {2f 61 70 69 5f 70 68 6f 6e 65 62 6f 6f 6b 2e 73 68 74 6d 6c } //01 00  /api_phonebook.shtml
		$a_00_2 = {2f 61 70 69 5f 63 61 6c 6c 6c 6f 67 2e 73 68 74 6d 6c } //01 00  /api_calllog.shtml
		$a_00_3 = {67 65 74 43 61 6c 6c 4c 6f 67 55 52 4c } //01 00  getCallLogURL
		$a_00_4 = {67 65 74 55 70 6c 6f 61 64 53 6d 73 58 4d 4c } //01 00  getUploadSmsXML
		$a_00_5 = {75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 73 } //00 00  uploadContacts
		$a_00_6 = {5d 04 00 } //00 7a 
	condition:
		any of ($a_*)
 
}