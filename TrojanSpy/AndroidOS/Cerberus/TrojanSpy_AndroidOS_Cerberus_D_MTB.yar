
rule TrojanSpy_AndroidOS_Cerberus_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Cerberus.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 72 61 62 62 69 6e 67 5f 6c 6f 63 6b 70 61 74 74 65 72 6e } //01 00  grabbing_lockpattern
		$a_00_1 = {67 72 61 62 62 69 6e 67 5f 67 6f 6f 67 6c 65 5f 61 75 74 68 65 6e 74 69 63 61 74 6f 72 } //01 00  grabbing_google_authenticator
		$a_00_2 = {72 75 6e 5f 61 64 6d 69 6e 5f 64 65 76 69 63 65 } //01 00  run_admin_device
		$a_00_3 = {73 6d 73 5f 6d 61 69 6c 69 6e 67 5f 70 68 6f 6e 65 62 6f 6f 6b } //01 00  sms_mailing_phonebook
		$a_00_4 = {73 65 6e 64 5f 6d 61 69 6c 69 6e 67 5f 73 6d 73 } //01 00  send_mailing_sms
		$a_00_5 = {72 61 74 5f 63 6f 6e 6e 65 63 74 } //00 00  rat_connect
		$a_00_6 = {5d 04 00 00 } //d7 5f 
	condition:
		any of ($a_*)
 
}