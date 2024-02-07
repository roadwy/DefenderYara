
rule MonitoringTool_AndroidOS_Phonespy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Phonespy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 61 6c 6c 5f 70 68 6f 6e 65 5f 6c 69 73 74 } //01 00  call_phone_list
		$a_00_1 = {66 6f 72 63 65 5f 69 6e 74 65 72 6e 65 74 } //01 00  force_internet
		$a_00_2 = {73 6d 73 5f 70 68 6f 6e 65 5f 6c 69 73 74 } //01 00  sms_phone_list
		$a_00_3 = {72 65 6d 6f 74 65 5f 77 69 70 65 } //01 00  remote_wipe
		$a_00_4 = {73 74 6f 70 5f 77 69 66 69 } //01 00  stop_wifi
		$a_00_5 = {64 69 73 61 62 6c 65 5f 72 6f 6f 74 } //01 00  disable_root
		$a_00_6 = {6c 6f 63 6b 5f 70 68 6f 6e 65 } //01 00  lock_phone
		$a_00_7 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 } //00 00  getInstalledApplications
	condition:
		any of ($a_*)
 
}