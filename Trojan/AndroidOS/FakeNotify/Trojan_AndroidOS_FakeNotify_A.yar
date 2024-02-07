
rule Trojan_AndroidOS_FakeNotify_A{
	meta:
		description = "Trojan:AndroidOS/FakeNotify.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 73 2f 72 61 77 2f 64 61 74 61 2e 64 62 } //01 00  res/raw/data.db
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 41 6e 64 49 6e 73 74 61 6c 6c } //01 00  DownloadAndInstall
		$a_01_2 = {6c 69 63 65 6e 73 65 53 63 72 65 65 6e 73 } //01 00  licenseScreens
		$a_01_3 = {61 64 64 53 65 6e 74 53 6d 73 } //01 00  addSentSms
		$a_01_4 = {52 65 70 65 61 74 69 6e 67 41 6c 61 72 6d 53 65 72 76 69 63 65 20 53 54 41 52 54 20 21 21 21 } //00 00  RepeatingAlarmService START !!!
	condition:
		any of ($a_*)
 
}