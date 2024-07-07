
rule Trojan_AndroidOS_SAgent_N_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgent.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 65 6c 65 70 68 6f 6e 79 5f 4d 4d 53 6d 73 4f 43 55 } //1 Telephony_MMSmsOCU
		$a_01_1 = {43 61 6c 6c 42 61 63 6b 5f 63 6d 63 63 5f 6e 65 74 } //1 CallBack_cmcc_net
		$a_01_2 = {63 6f 6d 2f 61 73 69 6f 6e 73 6b 79 2f 73 6d 73 6f 6e 65 73 } //1 com/asionsky/smsones
		$a_01_3 = {53 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e 45 78 } //1 SmsApplicationEx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}