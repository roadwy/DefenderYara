
rule Trojan_AndroidOS_Mamont_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Mamont.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 53 6d 73 48 69 73 74 6f 72 79 } //1 getSmsHistory
		$a_01_1 = {53 6d 73 53 75 62 4d 61 70 70 69 6e 67 } //1 SmsSubMapping
		$a_01_2 = {73 61 76 65 52 65 63 65 69 76 65 64 53 6d 73 } //1 saveReceivedSms
		$a_01_3 = {72 75 2f 63 76 76 2f 63 6f 72 65 2f 53 4d 53 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //1 ru/cvv/core/SMSBroadcastReceiver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}