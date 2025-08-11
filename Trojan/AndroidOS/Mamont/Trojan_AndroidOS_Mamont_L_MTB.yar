
rule Trojan_AndroidOS_Mamont_L_MTB{
	meta:
		description = "Trojan:AndroidOS/Mamont.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 6d 73 53 65 72 76 69 63 65 52 65 73 74 61 72 74 57 6f 72 6b 65 72 } //1 SmsServiceRestartWorker
		$a_01_1 = {70 72 6f 63 65 73 73 50 65 6e 64 69 6e 67 53 6d 73 4c 6f 67 73 } //1 processPendingSmsLogs
		$a_01_2 = {67 65 74 41 6c 6c 5f 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 73 } //1 getAll_phone_numbers
		$a_01_3 = {66 6f 75 6e 64 53 69 6d 43 61 72 64 73 } //1 foundSimCards
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}