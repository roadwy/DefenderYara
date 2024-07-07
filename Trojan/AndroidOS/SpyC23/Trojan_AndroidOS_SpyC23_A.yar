
rule Trojan_AndroidOS_SpyC23_A{
	meta:
		description = "Trojan:AndroidOS/SpyC23.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {69 6d 73 69 5f 73 5f 64 61 74 61 } //1 imsi_s_data
		$a_00_1 = {69 6d 73 69 5f 66 5f 6f 6c 64 5f 64 61 74 61 } //1 imsi_f_old_data
		$a_00_2 = {21 43 61 6c 6c 52 65 63 6f 72 64 69 6e 67 } //1 !CallRecording
		$a_00_3 = {21 53 6d 73 52 65 63 6f 72 64 69 6e 67 } //1 !SmsRecording
		$a_00_4 = {73 6b 69 70 50 72 6f 74 65 63 74 65 64 41 70 70 73 4d 65 73 73 61 67 65 } //1 skipProtectedAppsMessage
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}