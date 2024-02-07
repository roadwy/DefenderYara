
rule TrojanSpy_AndroidOS_Banker_A{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 65 72 6d 69 73 73 69 6f 6e 5f 72 65 71 5f 63 6f 64 65 5f 64 65 76 69 63 65 5f 61 64 6d 69 6e } //01 00  permission_req_code_device_admin
		$a_00_1 = {70 65 72 6d 69 73 73 69 6f 6e 5f 72 65 71 5f 63 6f 64 65 5f 73 6d 73 5f } //01 00  permission_req_code_sms_
		$a_00_2 = {76 61 6c 24 64 65 6d 6f 44 65 76 69 63 65 41 64 6d 69 6e } //01 00  val$demoDeviceAdmin
		$a_00_3 = {73 65 73 73 69 6f 6e 5f 67 63 6d 5f 72 65 67 5f 64 65 6c 69 76 65 72 79 } //01 00  session_gcm_reg_delivery
		$a_02_4 = {53 65 74 4a 61 76 61 53 63 72 69 70 74 45 6e 61 62 6c 65 64 90 01 02 53 75 70 65 72 53 65 72 76 69 63 65 90 00 } //01 00 
		$a_00_5 = {72 65 6d 6f 76 65 41 63 74 69 76 65 41 64 6d 69 6e } //00 00  removeActiveAdmin
	condition:
		any of ($a_*)
 
}