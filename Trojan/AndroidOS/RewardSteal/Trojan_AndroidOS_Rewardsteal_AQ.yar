
rule Trojan_AndroidOS_Rewardsteal_AQ{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.AQ,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 53 6d 73 44 61 74 61 54 6f 41 70 69 } //2 sendSmsDataToApi
		$a_01_1 = {69 74 73 69 63 2f 55 72 65 73 70 6f 6e 73 } //2 itsic/Urespons
		$a_01_2 = {69 74 73 69 63 2f 53 65 72 76 69 63 } //2 itsic/Servic
		$a_01_3 = {63 6f 6d 2f 6c 6f 64 2f 61 61 2f 55 73 65 72 } //2 com/lod/aa/User
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=4
 
}