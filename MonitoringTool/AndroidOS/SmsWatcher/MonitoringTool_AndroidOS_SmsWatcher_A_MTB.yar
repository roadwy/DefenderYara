
rule MonitoringTool_AndroidOS_SmsWatcher_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SmsWatcher.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 72 6a 62 6c 61 63 6b 62 6f 78 2f 73 77 6c 2f 53 4d 53 41 63 74 69 76 69 74 79 } //1 Lcom/rjblackbox/swl/SMSActivity
		$a_00_1 = {53 65 6e 74 20 62 79 20 53 4d 53 20 57 61 74 63 68 65 72 20 4c 69 74 65 } //1 Sent by SMS Watcher Lite
		$a_00_2 = {67 65 74 43 6f 6e 74 61 63 74 4e 61 6d 65 46 72 6f 6d 4e 75 6d 62 65 72 } //1 getContactNameFromNumber
		$a_00_3 = {53 6d 73 44 69 73 70 61 74 63 68 65 72 } //1 SmsDispatcher
		$a_00_4 = {53 4d 53 20 47 75 61 72 64 69 61 6e } //1 SMS Guardian
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}