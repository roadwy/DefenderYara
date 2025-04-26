
rule Trojan_AndroidOS_Copybara_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Copybara.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 5f 69 6e 6a 5f 6c 73 74 } //1 send_inj_lst
		$a_01_1 = {53 65 6e 64 5f 43 61 6c 6c 50 68 6f 6e 65 4e 75 6d 62 65 72 } //1 Send_CallPhoneNumber
		$a_01_2 = {47 65 74 5f 44 65 76 69 63 65 5f 43 61 6c 6c 4c 6f 67 73 } //1 Get_Device_CallLogs
		$a_01_3 = {53 65 6e 64 5f 53 4d 53 4d 65 73 73 61 67 65 5f 54 6f 4e 75 6d 62 65 72 } //1 Send_SMSMessage_ToNumber
		$a_01_4 = {53 65 6e 64 5f 4b 65 79 4c 6f 5f 56 69 65 77 73 } //1 Send_KeyLo_Views
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}