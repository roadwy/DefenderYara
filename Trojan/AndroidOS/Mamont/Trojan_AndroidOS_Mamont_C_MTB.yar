
rule Trojan_AndroidOS_Mamont_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Mamont.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 45 4e 44 49 4e 47 5f 53 4d 53 } //1 SENDING_SMS
		$a_01_1 = {53 6d 73 43 6f 6e 74 72 6f 6c 6c 65 72 } //1 SmsController
		$a_01_2 = {73 65 6e 64 46 72 6f 6d 41 6c 6c 53 69 6d 43 61 72 64 73 } //1 sendFromAllSimCards
		$a_01_3 = {67 65 74 4b 4f 52 4f 4e 41 5f 50 41 59 5f 50 41 59 4d 45 4e 54 5f 43 4f 4d 50 4c 45 54 45 44 } //1 getKORONA_PAY_PAYMENT_COMPLETED
		$a_01_4 = {54 65 6c 65 70 68 6f 6e 79 52 61 74 } //1 TelephonyRat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}