
rule Trojan_AndroidOS_Basbanke_M{
	meta:
		description = "Trojan:AndroidOS/Basbanke.M,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 6e 65 63 74 5f 54 4f 5f 53 65 72 76 65 72 5f 42 72 6f 6b 65 72 } //2 Connect_TO_Server_Broker
		$a_01_1 = {63 6f 6d 6d 61 6e 64 73 5f 46 72 6f 6d 50 43 } //2 commands_FromPC
		$a_01_2 = {53 65 6e 64 5f 43 65 72 74 61 69 6e 5f 53 4d 53 5f 54 6f 5f 41 64 6d 69 6e 5f 46 72 6f 6d 5f 41 6e 64 72 6f 69 64 } //2 Send_Certain_SMS_To_Admin_From_Android
		$a_01_3 = {5f 6e 6f 74 69 5f 72 65 70 6c 61 63 65 6d 65 6e 74 } //2 _noti_replacement
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}