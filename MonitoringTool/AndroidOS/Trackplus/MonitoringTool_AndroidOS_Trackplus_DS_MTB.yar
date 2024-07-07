
rule MonitoringTool_AndroidOS_Trackplus_DS_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Trackplus.DS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 70 79 20 61 6e 64 20 53 63 72 65 65 6e 20 4f 6e } //1 Spy and Screen On
		$a_00_1 = {53 50 59 32 4d 4f 42 49 4c 45 } //1 SPY2MOBILE
		$a_00_2 = {73 6d 73 5f 68 69 73 74 6f 72 79 } //1 sms_history
		$a_00_3 = {43 4f 4e 54 41 43 54 53 5f 48 41 53 48 } //1 CONTACTS_HASH
		$a_00_4 = {49 53 5f 53 45 4e 44 5f 49 4e 46 4f } //1 IS_SEND_INFO
		$a_00_5 = {63 61 6c 6c 5f 68 69 73 74 6f 72 79 } //1 call_history
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}