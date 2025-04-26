
rule TrojanSpy_AndroidOS_Faketoken_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Faketoken.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 63 6f 6e 74 72 6f 6c 6c 65 72 2e 70 68 70 3f 6d 6f 64 65 3d } //1 /controller.php?mode=
		$a_01_1 = {69 73 44 65 6c 65 74 65 53 6d 73 } //1 isDeleteSms
		$a_01_2 = {73 63 68 65 63 6b 5f 64 65 6c 5f 6d 73 67 } //1 scheck_del_msg
		$a_01_3 = {63 6f 6e 73 74 5f 69 64 5f 73 65 6e 64 5f 73 6d 73 } //1 const_id_send_sms
		$a_01_4 = {72 65 67 69 73 74 65 72 42 6f 74 } //1 registerBot
		$a_01_5 = {75 70 53 65 72 76 65 72 53 6d 73 4c 69 73 74 } //1 upServerSmsList
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}