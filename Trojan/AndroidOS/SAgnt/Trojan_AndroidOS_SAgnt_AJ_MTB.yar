
rule Trojan_AndroidOS_SAgnt_AJ_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AJ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 68 61 70 70 79 70 68 6f 6e 65 2e 74 6b 2f 69 6e 76 69 74 65 2e 68 74 6d } //1 www.happyphone.tk/invite.htm
		$a_01_1 = {72 6f 73 65 70 68 70 2e 75 73 32 39 2e 69 69 73 6f 6b 2e 6e 65 74 } //1 rosephp.us29.iisok.net
		$a_01_2 = {73 70 5f 74 79 70 65 5f 62 6c 5f 73 65 72 76 65 72 } //1 sp_type_bl_server
		$a_01_3 = {73 70 5f 74 79 70 65 5f 6c 61 73 74 5f 61 6c 6c 5f 63 61 6c 6c 5f 6c 6f 67 5f 74 69 6d 65 } //1 sp_type_last_all_call_log_time
		$a_01_4 = {73 70 5f 74 79 70 65 5f 6c 61 73 74 5f 61 6c 6c 5f 73 6d 73 5f 74 69 6d 65 } //1 sp_type_last_all_sms_time
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}