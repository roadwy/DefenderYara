
rule Trojan_AndroidOS_Riltok_D{
	meta:
		description = "Trojan:AndroidOS/Riltok.D,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 6f 76 65 5f 73 6d 73 5f 63 6c 69 65 6e 74 } //2 move_sms_client
		$a_00_1 = {70 75 73 68 5f 65 6e 64 5f 73 74 61 74 75 73 } //2 push_end_status
		$a_00_2 = {69 73 52 65 71 75 65 73 74 4b 69 6c 6c 65 64 } //2 isRequestKilled
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}