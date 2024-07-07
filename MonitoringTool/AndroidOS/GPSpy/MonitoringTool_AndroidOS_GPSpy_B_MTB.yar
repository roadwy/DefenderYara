
rule MonitoringTool_AndroidOS_GPSpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/GPSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 64 61 74 61 62 61 63 6b 75 70 2e 62 6f } //1 com.databackup.bo
		$a_01_1 = {67 70 73 5f 72 6f 6f 74 5f 6c 6c } //1 gps_root_ll
		$a_01_2 = {49 6e 74 65 72 6e 65 74 4c 6f 63 61 74 69 6f 6e 4c 6f 61 64 65 72 } //1 InternetLocationLoader
		$a_01_3 = {53 65 74 74 69 6e 67 73 41 63 74 69 76 69 74 79 5f 70 65 72 6d 69 73 73 69 6f 6e 73 5f 72 65 71 75 69 72 65 64 } //1 SettingsActivity_permissions_required
		$a_01_4 = {57 69 2d 46 69 20 74 72 61 63 6b } //1 Wi-Fi track
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}