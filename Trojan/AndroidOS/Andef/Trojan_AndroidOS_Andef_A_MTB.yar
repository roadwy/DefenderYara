
rule Trojan_AndroidOS_Andef_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Andef.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 43 6f 6e 74 61 63 74 50 68 6f 6e 65 } //1 getContactPhone
		$a_01_1 = {73 65 6e 64 54 6f 42 6c 61 63 6b 5f 43 6c 69 63 6b } //1 sendToBlack_Click
		$a_01_2 = {63 68 6b 4e 6f 74 47 65 74 53 4d 53 } //1 chkNotGetSMS
		$a_01_3 = {63 68 6b 4e 6f 74 47 65 74 43 61 6c 6c } //1 chkNotGetCall
		$a_01_4 = {74 78 74 5f 61 64 64 5f 62 6c 61 63 6b 5f 77 61 72 6e 69 6e 67 5f 70 61 72 61 6d 73 5f 6d 65 73 73 61 67 65 } //1 txt_add_black_warning_params_message
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}