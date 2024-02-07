
rule MonitoringTool_AndroidOS_Sledat_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Sledat.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 6c 65 64 61 74 5f 53 4d 53 } //01 00  Sledat_SMS
		$a_00_1 = {76 6d 65 73 6e 69 6b 2e 70 68 70 } //01 00  vmesnik.php
		$a_00_2 = {73 6c 65 64 61 74 2e 63 6c 69 65 6e 74 2e 73 6c 65 64 61 74 5f } //01 00  sledat.client.sledat_
		$a_00_3 = {2f 64 6f 64 61 74 6b 69 2f 61 6e 64 72 6f 69 64 2f 75 70 6c 6f 61 64 2e 70 68 70 } //01 00  /dodatki/android/upload.php
		$a_00_4 = {67 65 74 69 6e 66 6f } //01 00  getinfo
		$a_00_5 = {73 64 5f 74 72 61 63 6b 65 72 5f 64 61 74 61 } //00 00  sd_tracker_data
	condition:
		any of ($a_*)
 
}