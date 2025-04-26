
rule MonitoringTool_AndroidOS_Cobblerone_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Cobblerone.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {50 6c 65 61 73 65 20 63 61 6c 6c 20 78 78 78 78 78 78 78 78 20 74 6f 20 66 69 6e 64 20 74 68 65 20 70 68 6f 6e 65 20 6f 77 6e 65 72 2e } //1 Please call xxxxxxxx to find the phone owner.
		$a_00_1 = {57 69 70 65 50 68 6f 6e 65 } //1 WipePhone
		$a_01_2 = {57 49 50 45 5f 53 44 43 41 52 44 5f 53 4d 53 } //1 WIPE_SDCARD_SMS
		$a_00_3 = {66 6f 72 63 65 5f 6c 6f 63 6b } //1 force_lock
		$a_00_4 = {2f 70 68 6f 6e 65 6c 6f 63 6b 5f 74 65 73 74 5f 66 6f 6c 64 65 72 2f } //1 /phonelock_test_folder/
		$a_00_5 = {73 6d 73 5f 74 6f 5f 68 69 64 65 5f 73 64 63 61 72 64 } //1 sms_to_hide_sdcard
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}