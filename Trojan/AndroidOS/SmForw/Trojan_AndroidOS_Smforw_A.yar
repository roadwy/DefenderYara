
rule Trojan_AndroidOS_Smforw_A{
	meta:
		description = "Trojan:AndroidOS/Smforw.A,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 61 73 5f 73 65 74 5f 73 65 6e 64 5f 65 6d 61 69 6c 5f 61 63 63 6f 75 6e 74 } //2 has_set_send_email_account
		$a_01_1 = {69 73 5f 69 6e 69 74 5f 65 6e 64 5f 74 69 6d 65 } //2 is_init_end_time
		$a_01_2 = {65 6d 61 69 6c 5f 6d 65 73 73 61 67 65 5f 63 6f 6e 74 61 63 74 73 5f 73 77 69 74 63 68 } //2 email_message_contacts_switch
		$a_01_3 = {68 61 73 5f 73 65 6e 64 5f 70 68 6f 6e 65 5f 69 6e 66 6f } //2 has_send_phone_info
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}