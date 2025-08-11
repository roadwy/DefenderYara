
rule Trojan_AndroidOS_Mamont_I_MTB{
	meta:
		description = "Trojan:AndroidOS/Mamont.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 75 2f 70 75 74 69 73 68 61 2f 61 70 70 2f 53 6d 73 53 65 72 76 69 63 65 } //1 ru/putisha/app/SmsService
		$a_01_1 = {67 65 74 5f 6d 65 73 73 61 67 65 5f 68 69 73 74 6f 72 79 } //1 get_message_history
		$a_01_2 = {53 6d 73 53 75 62 4d 61 70 70 69 6e 67 } //1 SmsSubMapping
		$a_01_3 = {67 65 74 5f 63 61 6c 6c 73 5f 68 69 73 74 6f 72 79 } //1 get_calls_history
		$a_01_4 = {d0 9d d0 9e d0 92 d0 9e d0 95 20 53 4d 53 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}