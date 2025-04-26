
rule TrojanSpy_AndroidOS_SmsBot_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsBot.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 6f 6d 6f 6e 34 38 2e 72 75 } //1 gomon48.ru
		$a_01_1 = {69 73 5f 64 69 76 69 63 65 5f 61 64 6d 69 6e 5f 61 62 73 6f 6c 75 74 65 } //1 is_divice_admin_absolute
		$a_00_2 = {63 6f 6e 73 74 5f 69 64 5f 73 65 6e 64 5f 73 6d 73 } //1 const_id_send_sms
		$a_01_3 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f 73 65 6e 74 } //1 content://sms/sent
		$a_01_4 = {61 70 70 2e 73 69 78 2e 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 app.six.MainActivity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}