
rule Trojan_AndroidOS_SmsAgent_G{
	meta:
		description = "Trojan:AndroidOS/SmsAgent.G,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 79 73 5f 6d 65 73 73 61 67 65 5f 61 64 64 72 65 73 73 } //2 sys_message_address
		$a_01_1 = {73 79 73 5f 73 65 6e 64 5f 63 6f 6e 74 65 6e 74 73 } //2 sys_send_contents
		$a_01_2 = {73 79 73 5f 6d 61 6b 65 5f 77 65 62 5f 71 75 69 63 6b } //2 sys_make_web_quick
		$a_01_3 = {54 6e 6b 4c 69 62 41 63 63 65 73 73 } //2 TnkLibAccess
		$a_01_4 = {61 66 66 6d 6f 62 2e 74 6f 72 6e 69 6b 61 2e 63 6f 6d 2f 73 65 72 76 69 63 65 5f 6c 69 62 2e 70 68 70 } //2 affmob.tornika.com/service_lib.php
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=8
 
}