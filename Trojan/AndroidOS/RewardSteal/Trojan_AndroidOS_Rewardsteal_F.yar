
rule Trojan_AndroidOS_Rewardsteal_F{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.F,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 73 6d 73 2e 61 70 70 6b 6b 66 66 72 72 64 64 } //1 com.sms.appkkffrrdd
		$a_01_1 = {53 4d 53 20 73 61 76 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 74 6f 20 74 68 65 20 73 65 72 76 65 72 } //1 SMS saved successfully to the server
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}