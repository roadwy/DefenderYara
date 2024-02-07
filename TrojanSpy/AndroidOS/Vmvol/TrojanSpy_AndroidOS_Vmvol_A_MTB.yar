
rule TrojanSpy_AndroidOS_Vmvol_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Vmvol.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 70 64 61 74 65 52 65 6d 6f 74 65 53 6d 73 53 74 61 74 75 73 } //01 00  updateRemoteSmsStatus
		$a_00_1 = {75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 73 } //01 00  uploadContacts
		$a_00_2 = {72 65 61 64 53 69 6d 43 6f 6e 74 61 63 74 } //01 00  readSimContact
		$a_01_3 = {57 49 52 45 54 41 50 5f 50 4b 47 4e 41 4d 45 } //01 00  WIRETAP_PKGNAME
		$a_00_4 = {4d 6f 6e 69 74 6f 72 49 6e 73 74 61 6c 6c 65 64 } //01 00  MonitorInstalled
		$a_01_5 = {52 45 51 55 45 53 54 5f 43 4f 44 45 5f 49 4e 53 54 41 4c 4c 5f 41 50 4b } //00 00  REQUEST_CODE_INSTALL_APK
		$a_00_6 = {be 8d 00 00 } //05 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_AndroidOS_Vmvol_A_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/Vmvol.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 75 70 6c 6f 61 64 53 6d 73 2e 68 74 6d } //01 00  /uploadSms.htm
		$a_00_1 = {2f 75 70 6c 6f 61 64 41 6c 62 75 6d 2e 68 74 6d } //01 00  /uploadAlbum.htm
		$a_00_2 = {2f 75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 2e 68 74 6d } //01 00  /uploadContact.htm
		$a_00_3 = {2f 41 75 74 6f 52 75 6e 52 65 63 65 69 76 65 72 3b } //01 00  /AutoRunReceiver;
		$a_00_4 = {69 73 55 70 6c 6f 61 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 52 65 63 6f 72 64 } //01 00  isUploadEnvironmentRecord
		$a_00_5 = {73 65 74 55 70 6c 6f 61 64 43 61 6c 6c 6c 6f 67 } //00 00  setUploadCalllog
		$a_00_6 = {5d 04 00 00 } //f2 4f 
	condition:
		any of ($a_*)
 
}