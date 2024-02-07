
rule MonitoringTool_AndroidOS_TheftAware_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/TheftAware.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 61 74 2e 69 74 61 67 65 6e 74 73 2e 74 61 2e 61 70 6b } //01 00  /system/app/at.itagents.ta.apk
		$a_00_1 = {54 68 65 66 74 41 77 61 72 65 49 6e 73 74 61 6c 6c 65 72 2e 74 65 6d 70 2e 61 70 6b } //01 00  TheftAwareInstaller.temp.apk
		$a_00_2 = {54 68 65 66 74 41 77 61 72 65 53 65 72 76 69 63 65 } //01 00  TheftAwareService
		$a_00_3 = {61 74 2e 69 74 61 67 65 6e 74 73 2e 74 61 5f 73 65 74 75 70 5f 6d 66 } //01 00  at.itagents.ta_setup_mf
		$a_00_4 = {77 77 77 2e 74 68 65 66 74 61 77 61 72 65 2e 63 6f 6d } //01 00  www.theftaware.com
		$a_00_5 = {2f 74 6d 70 2f 61 74 2e 69 74 61 67 65 6e 74 73 2e 74 61 2e 6c 6f 67 } //00 00  /tmp/at.itagents.ta.log
	condition:
		any of ($a_*)
 
}