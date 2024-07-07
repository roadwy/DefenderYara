
rule MonitoringTool_AndroidOS_SpyHuman_C_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SpyHuman.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {61 70 69 73 70 79 68 75 6d 61 6e 2e 63 6f 6d } //1 apispyhuman.com
		$a_00_1 = {61 63 74 69 76 69 74 79 5f 6d 6f 6e 69 74 6f 72 69 6e 67 5f 6f 70 61 74 69 6f 6e } //1 activity_monitoring_opation
		$a_00_2 = {69 6e 73 74 61 6c 6c 5f 4d 6f 6e 69 74 6f 72 69 6e 67 5f 54 79 70 65 5f 61 63 74 69 76 69 74 79 } //1 install_Monitoring_Type_activity
		$a_00_3 = {52 65 61 64 61 6c 6c 63 6f 6e 74 65 63 74 73 } //1 Readallcontects
		$a_00_4 = {41 70 70 46 65 74 75 72 65 73 4d 61 6e } //1 AppFeturesMan
		$a_00_5 = {42 72 6f 64 63 61 73 74 5f 43 61 6c 6c } //1 Brodcast_Call
		$a_00_6 = {73 6d 73 75 70 6c 6f 61 64 } //1 smsupload
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}