
rule Trojan_AndroidOS_Rewardsteal_Q{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.Q,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 69 63 69 63 69 62 61 6e 6b } //1 com.example.icicibank
		$a_01_1 = {6d 65 73 73 61 67 65 20 20 6e 6f 74 20 73 65 6e 64 } //1 message  not send
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_AndroidOS_Rewardsteal_Q_2{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.Q,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 65 62 2f 61 70 69 2f 75 73 65 72 2f 73 6d 73 } //2 web/api/user/sms
		$a_00_1 = {61 70 69 2f 75 73 65 72 2f 73 74 65 70 31 } //2 api/user/step1
		$a_00_2 = {54 71 41 63 74 69 76 69 74 79 } //2 TqActivity
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}