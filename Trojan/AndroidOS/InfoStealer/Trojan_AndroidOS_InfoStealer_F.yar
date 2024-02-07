
rule Trojan_AndroidOS_InfoStealer_F{
	meta:
		description = "Trojan:AndroidOS/InfoStealer.F,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 0b 00 00 02 00 "
		
	strings :
		$a_01_0 = {75 70 6c 6f 61 64 46 69 72 73 74 } //02 00  uploadFirst
		$a_01_1 = {75 70 6c 6f 61 64 53 65 63 6f 6e 64 } //02 00  uploadSecond
		$a_01_2 = {66 65 74 63 68 43 55 73 65 72 } //02 00  fetchCUser
		$a_01_3 = {64 6f 63 75 6d 65 6e 74 2e 61 6c 6c 2e 6c 6f 67 69 6e 2e 63 6c 69 63 6b 28 29 3b } //01 00  document.all.login.click();
		$a_01_4 = {73 68 6f 75 6c 64 49 6e 74 65 72 63 65 70 74 52 65 71 75 65 73 74 } //01 00  shouldInterceptRequest
		$a_00_5 = {61 63 63 65 73 73 5f 74 6f 6b 65 6e 3d } //01 00  access_token=
		$a_01_6 = {64 65 76 69 63 65 2d 62 61 73 65 64 } //01 00  device-based
		$a_01_7 = {63 6f 6d 2f 3f 5f 72 64 72 } //01 00  com/?_rdr
		$a_01_8 = {61 64 73 6d 61 6e 61 67 65 72 } //01 00  adsmanager
		$a_00_9 = {63 5f 75 73 65 72 } //01 00  c_user
		$a_01_10 = {73 61 76 65 53 74 61 74 75 73 } //00 00  saveStatus
	condition:
		any of ($a_*)
 
}