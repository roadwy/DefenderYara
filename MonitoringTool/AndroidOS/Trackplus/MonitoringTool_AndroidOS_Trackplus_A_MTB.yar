
rule MonitoringTool_AndroidOS_Trackplus_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Trackplus.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 73 70 79 32 6d 6f 62 69 6c 65 2f 6c 69 67 68 74 } //1 com/spy2mobile/light
		$a_00_1 = {67 70 73 5f 72 6f 6f 74 5f 6c 6c } //1 gps_root_ll
		$a_00_2 = {54 72 61 63 6b 65 72 4c 6f 63 61 74 69 6f 6e } //1 TrackerLocation
		$a_00_3 = {67 65 74 4c 61 73 74 4b 6e 6f 77 6e 4c 6f 63 61 74 69 6f 6e } //1 getLastKnownLocation
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule MonitoringTool_AndroidOS_Trackplus_A_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/Trackplus.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {74 72 61 63 6b 65 72 70 6c 75 73 2e 64 62 } //1 trackerplus.db
		$a_00_1 = {43 6f 6f 72 64 73 4d 61 6e 61 67 65 72 20 72 65 61 64 66 72 6f 6d 44 62 } //1 CoordsManager readfromDb
		$a_00_2 = {53 70 79 20 61 6e 64 20 53 63 72 65 65 6e 20 4f 6e } //1 Spy and Screen On
		$a_00_3 = {54 72 61 63 6b 65 72 4c 6f 63 61 74 69 6f 6e 2e 69 73 44 69 73 74 61 6e 63 65 56 61 6c 69 64 } //1 TrackerLocation.isDistanceValid
		$a_00_4 = {4c 72 75 2f 69 6e 74 65 63 68 2f 6c 69 62 2f 54 72 61 63 6b 65 72 53 65 72 76 69 63 65 } //1 Lru/intech/lib/TrackerService
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}