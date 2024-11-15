
rule Trojan_AndroidOS_Rewardsteal_AE{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.AE,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 6c 65 61 73 65 20 65 6e 74 65 72 20 62 6f 74 68 20 6d 6f 62 69 6c 65 20 6e 75 6d 62 65 72 20 61 6e 64 20 4d 50 49 4e } //2 Please enter both mobile number and MPIN
		$a_01_1 = {53 4d 53 20 70 65 72 6d 69 73 73 69 6f 6e 73 20 61 6c 72 65 61 64 79 20 67 72 61 6e 74 65 64 } //2 SMS permissions already granted
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}