
rule Trojan_AndroidOS_Rewardsteal_QP{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.QP,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 73 43 68 65 63 6b 69 6e 67 46 6f 72 53 6d 73 } //2 isCheckingForSms
		$a_01_1 = {73 74 61 72 74 53 6d 73 43 68 65 63 6b 69 6e 67 } //2 startSmsChecking
		$a_01_2 = {73 65 74 53 6d 73 53 75 62 6d 69 74 74 65 64 } //2 setSmsSubmitted
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}