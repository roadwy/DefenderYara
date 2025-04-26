
rule Backdoor_AndroidOS_Maxit_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Maxit.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 32 64 6d 2e 69 6d 61 78 74 65 72 2e 6e 65 74 } //1 c2dm.imaxter.net
		$a_01_1 = {53 4d 53 5f 41 43 43 45 53 53 } //1 SMS_ACCESS
		$a_00_2 = {64 69 72 65 63 74 72 65 70 6c 79 6d 6f 62 69 6c 65 } //1 directreplymobile
		$a_00_3 = {73 70 47 65 6f 44 61 74 61 } //1 spGeoData
		$a_01_4 = {52 45 50 4c 59 5f 42 4c 4f 43 4b 5f 4e 55 4d 42 45 52 } //1 REPLY_BLOCK_NUMBER
		$a_03_5 = {4c 63 6f 6d 2f 6d 78 6d 6f 62 69 6c 65 [0-17] 50 75 73 68 41 64 73 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}