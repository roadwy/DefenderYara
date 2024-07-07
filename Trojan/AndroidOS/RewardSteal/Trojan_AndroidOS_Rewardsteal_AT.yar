
rule Trojan_AndroidOS_Rewardsteal_AT{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.AT,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 70 69 2f 75 73 65 72 2f 73 74 65 70 32 } //2 com/api/user/step2
		$a_01_1 = {64 69 67 69 74 61 6c 70 6f 73 74 65 72 2f 50 65 72 73 6f 6e 61 6c 41 63 74 69 76 69 74 79 } //2 digitalposter/PersonalActivity
		$a_01_2 = {65 64 67 65 63 72 65 64 69 74 73 61 70 70 2e 63 6f 6d 2f 61 70 69 } //2 edgecreditsapp.com/api
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}