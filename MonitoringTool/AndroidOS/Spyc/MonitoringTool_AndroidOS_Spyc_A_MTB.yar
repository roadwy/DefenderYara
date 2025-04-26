
rule MonitoringTool_AndroidOS_Spyc_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Spyc.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 68 6b 5f 6f 75 74 67 6f 69 6e 67 5f 73 6d 73 } //1 chk_outgoing_sms
		$a_00_1 = {67 65 74 4c 6f 63 61 74 69 6f 6e 4c 6f 67 46 72 6f 6d 44 61 74 61 62 61 73 65 } //1 getLocationLogFromDatabase
		$a_00_2 = {43 41 4c 4c 53 5f 46 44 55 52 41 54 49 4f 4e } //1 CALLS_FDURATION
		$a_00_3 = {43 48 4b 5f 49 4e 43 4f 4d 49 4e 47 5f 43 41 4c 4c } //1 CHK_INCOMING_CALL
		$a_00_4 = {4c 63 6f 6d 2f 62 6c 75 75 6d 69 2f 73 70 79 63 6f 6e 74 72 6f 6c } //1 Lcom/bluumi/spycontrol
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}