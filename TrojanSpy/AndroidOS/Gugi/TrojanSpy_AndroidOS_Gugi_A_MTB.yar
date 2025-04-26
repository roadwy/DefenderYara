
rule TrojanSpy_AndroidOS_Gugi_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Gugi.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {72 75 2e 64 72 69 6e 6b 2e 6c 69 6d 65 } //2 ru.drink.lime
		$a_00_1 = {73 65 74 5f 73 6d 73 5f 73 74 61 74 75 73 } //1 set_sms_status
		$a_00_2 = {73 65 74 5f 74 61 73 6b 5f 73 74 61 74 75 73 } //1 set_task_status
		$a_00_3 = {38 30 2e 38 37 2e 32 30 35 2e 31 32 36 } //1 80.87.205.126
		$a_00_4 = {65 78 69 73 74 5f 62 61 6e 6b 5f 61 70 70 } //1 exist_bank_app
		$a_00_5 = {72 2e 64 2e 6c 2e 73 6d 73 5f 73 65 6e 74 } //1 r.d.l.sms_sent
		$a_00_6 = {63 6c 69 65 6e 74 5f 70 61 73 73 77 6f 72 64 } //1 client_password
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}