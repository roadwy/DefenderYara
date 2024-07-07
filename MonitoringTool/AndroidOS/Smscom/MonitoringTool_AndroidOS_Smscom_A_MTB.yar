
rule MonitoringTool_AndroidOS_Smscom_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Smscom.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 46 72 6f 6d 53 6d 73 4d 65 73 73 61 67 65 } //1 CreateFromSmsMessage
		$a_01_1 = {73 65 74 53 6d 73 53 65 72 76 69 63 65 4c 69 73 74 65 6e 65 72 } //1 setSmsServiceListener
		$a_01_2 = {67 65 74 41 6c 6c 55 73 65 64 50 68 6f 6e 65 73 } //1 getAllUsedPhones
		$a_01_3 = {53 4d 53 52 65 63 65 69 76 65 72 53 65 72 76 69 63 65 } //1 SMSReceiverService
		$a_01_4 = {73 61 76 65 55 73 65 72 44 61 74 61 } //1 saveUserData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}