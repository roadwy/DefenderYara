
rule TrojanSpy_AndroidOS_Gugi_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Gugi.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 65 43 2f 77 65 65 77 79 75 2f 69 4f 69 6a 75 43 } //1 seC/weewyu/iOijuC
		$a_00_1 = {63 6f 6d 6d 61 6e 64 4f 62 53 65 72 76 65 72 } //1 commandObServer
		$a_00_2 = {63 6f 6d 2e 67 6f 6f 67 69 65 2e 73 79 73 74 65 6d 2e 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 com.googie.system.MainActivity
		$a_00_3 = {67 65 74 20 73 6d 73 5f 6c 69 73 74 } //1 get sms_list
		$a_00_4 = {63 6f 6e 73 74 5f 69 64 5f 73 65 6e 64 5f 73 6d 73 } //1 const_id_send_sms
		$a_00_5 = {61 6c 61 72 6d 5f 63 68 65 63 6b 5f 63 6f 6e 6e 65 63 74 65 64 } //1 alarm_check_connected
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}