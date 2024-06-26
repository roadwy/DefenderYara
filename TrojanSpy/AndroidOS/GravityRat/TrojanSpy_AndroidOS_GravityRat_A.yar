
rule TrojanSpy_AndroidOS_GravityRat_A{
	meta:
		description = "TrojanSpy:AndroidOS/GravityRat.A,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 77 68 69 73 6b 65 79 2e 72 65 73 74 61 72 74 } //01 00  com.android.whiskey.restart
		$a_01_1 = {73 6d 73 5f 66 69 6c 65 5f 73 74 61 74 75 73 } //01 00  sms_file_status
		$a_01_2 = {63 61 6c 6c 5f 66 69 6c 65 5f 73 74 61 74 75 73 } //01 00  call_file_status
		$a_01_3 = {67 65 74 5f 43 44 5f 43 61 6c 6c 73 4c 6f 67 73 } //01 00  get_CD_CallsLogs
		$a_01_4 = {2f 41 6e 64 72 6f 69 64 2f 6f 77 77 2e 74 78 74 } //01 00  /Android/oww.txt
		$a_01_5 = {4c 6f 63 61 74 69 6f 6e 20 6e 6f 74 20 61 76 61 69 6c 61 62 6c 65 20 72 69 67 68 74 20 6e 6f 77 } //01 00  Location not available right now
		$a_01_6 = {61 6e 64 72 6f 69 64 73 64 6b 73 74 72 65 61 6d 2e 63 6f 6d } //01 00  androidsdkstream.com
		$a_01_7 = {68 69 20 62 61 63 6b 20 72 65 73 74 61 72 74 69 6e 67 21 21 20 3a 44 } //01 00  hi back restarting!! :D
		$a_01_8 = {63 6c 2e 6c 6f 67 } //01 00  cl.log
		$a_01_9 = {2f 63 64 6d 73 2e 6c 6f 67 } //01 00  /cdms.log
		$a_01_10 = {2f 6d 73 2e 6c 6f 67 } //01 00  /ms.log
		$a_01_11 = {47 65 74 41 63 74 69 76 65 50 72 69 76 61 74 65 44 6f 6d 61 69 6e } //01 00  GetActivePrivateDomain
		$a_01_12 = {73 6f 73 61 66 65 2e 63 6f 2e 69 6e } //00 00  sosafe.co.in
		$a_00_13 = {5d 04 00 00 } //3f ec 
	condition:
		any of ($a_*)
 
}