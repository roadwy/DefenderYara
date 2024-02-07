
rule TrojanSpy_AndroidOS_Asacub_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Asacub.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,2a 00 2a 00 0b 00 00 0a 00 "
		
	strings :
		$a_00_0 = {44 65 76 69 63 65 41 64 6d 69 6e 53 61 6d 70 6c 65 } //0a 00  DeviceAdminSample
		$a_00_1 = {41 63 74 69 76 69 74 79 47 65 74 43 43 } //0a 00  ActivityGetCC
		$a_00_2 = {53 4d 53 4d 6f 6e 69 74 6f 72 } //0a 00  SMSMonitor
		$a_01_3 = {54 75 6b 54 75 6b } //0a 00  TukTuk
		$a_00_4 = {2f 73 73 6c 5f 74 6d 70 2f } //01 00  /ssl_tmp/
		$a_01_5 = {62 6c 6f 63 6b 5f 70 68 6f 6e 65 } //01 00  block_phone
		$a_01_6 = {67 65 74 5f 68 69 73 74 6f 72 79 } //01 00  get_history
		$a_01_7 = {67 65 74 5f 63 6f 6e 74 61 63 74 73 } //01 00  get_contacts
		$a_01_8 = {67 65 74 5f 6c 69 73 74 61 70 70 } //01 00  get_listapp
		$a_01_9 = {73 65 6e 64 5f 75 73 73 64 } //01 00  send_ussd
		$a_01_10 = {67 65 74 5f 63 63 } //00 00  get_cc
	condition:
		any of ($a_*)
 
}