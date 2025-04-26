
rule MonitoringTool_AndroidOS_Trackplus_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Trackplus.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 69 6e 74 65 6c 36 34 66 72 65 2e } //1 .intel64fre.
		$a_01_1 = {49 6e 74 65 72 6e 65 74 4c 6f 63 61 74 69 6f 6e 4c 6f 61 64 65 72 } //1 InternetLocationLoader
		$a_01_2 = {53 65 74 74 69 6e 67 73 41 63 74 69 76 69 74 79 5f 70 65 72 6d 69 73 73 69 6f 6e 73 5f 72 65 71 75 69 72 65 64 } //1 SettingsActivity_permissions_required
		$a_01_3 = {57 69 66 69 52 61 77 7b 53 63 61 6e 52 65 73 75 6c 74 4c 69 73 74 3d } //1 WifiRaw{ScanResultList=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}