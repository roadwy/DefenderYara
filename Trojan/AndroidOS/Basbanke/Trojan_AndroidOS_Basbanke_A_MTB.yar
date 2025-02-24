
rule Trojan_AndroidOS_Basbanke_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Basbanke.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 69 64 65 5f 41 70 70 44 61 74 61 5f 49 6e 66 6f } //1 Hide_AppData_Info
		$a_01_1 = {47 65 74 5f 44 65 76 69 63 65 5f 43 61 6c 6c 4c 6f 67 73 } //1 Get_Device_CallLogs
		$a_01_2 = {53 65 6e 64 5f 43 61 6c 6c 50 68 6f 6e 65 4e 75 6d 62 65 72 } //1 Send_CallPhoneNumber
		$a_01_3 = {53 65 6e 64 5f 53 4d 53 4d 65 73 73 61 67 65 5f 54 6f 4e 75 6d 62 65 72 } //1 Send_SMSMessage_ToNumber
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}