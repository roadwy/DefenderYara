
rule MonitoringTool_AndroidOS_SPAPP_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SPAPP.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 50 41 50 50 20 4d 6f 6e 69 74 6f 72 69 6e 67 } //01 00  SPAPP Monitoring
		$a_00_1 = {77 77 77 2e 53 70 79 2d 64 61 74 61 63 65 6e 74 65 72 2e 63 6f 6d 2f 73 65 6e 64 5f 64 61 74 61 2e 70 68 70 } //01 00  www.Spy-datacenter.com/send_data.php
		$a_00_2 = {63 6f 6d 2e 73 70 79 61 70 70 2e 77 65 62 62 72 6f 77 73 65 72 } //01 00  com.spyapp.webbrowser
		$a_00_3 = {70 68 5f 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 5f 72 69 67 68 74 73 5f 65 6e 61 62 6c 65 64 } //01 00  ph_administrator_rights_enabled
		$a_00_4 = {65 6e 61 62 6c 65 5f 72 65 6d 6f 74 65 5f 77 69 70 65 } //01 00  enable_remote_wipe
		$a_00_5 = {72 65 63 6f 72 64 69 6e 67 5f 70 68 6f 6e 65 } //00 00  recording_phone
	condition:
		any of ($a_*)
 
}