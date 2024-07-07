
rule MonitoringTool_AndroidOS_Nisso_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Nisso.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {4d 6f 6e 69 74 6f 72 52 6f 6f 74 41 63 74 69 76 69 74 79 } //1 MonitorRootActivity
		$a_00_1 = {72 75 2e 6e 69 69 73 6f 6b 62 2e 6d 63 63 } //1 ru.niisokb.mcc
		$a_00_2 = {43 6f 6d 6d 61 6e 64 53 65 74 43 6f 72 70 6f 72 61 74 65 53 69 6d 73 } //1 CommandSetCorporateSims
		$a_00_3 = {53 63 72 65 65 6e 4c 6f 63 6b 52 6f 6f 74 41 63 74 69 76 69 74 79 } //1 ScreenLockRootActivity
		$a_00_4 = {43 6f 6d 6d 61 6e 64 52 65 67 69 73 74 65 72 44 65 76 69 63 65 49 6e 66 6f } //1 CommandRegisterDeviceInfo
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}