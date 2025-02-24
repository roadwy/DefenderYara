
rule Trojan_AndroidOS_Rewardsteal_FT{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.FT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 68 6f 6e 65 20 4f 52 20 53 4d 53 20 70 65 72 6d 69 73 73 69 6f 6e 20 69 73 20 6e 6f 74 20 67 72 61 6e 74 65 64 } //1 Phone OR SMS permission is not granted
		$a_01_1 = {53 4d 53 20 53 41 56 45 20 54 4f 20 50 41 4e 45 20 3a } //1 SMS SAVE TO PANE :
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_AndroidOS_Rewardsteal_FT_2{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.FT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {69 64 66 63 2d 34 66 35 34 61 2d 64 65 66 61 75 6c 74 2d 72 74 64 62 2e 66 69 72 65 62 61 73 65 69 6f 2e 63 6f 6d } //1 idfc-4f54a-default-rtdb.firebaseio.com
		$a_00_1 = {73 74 75 64 65 6e 74 37 30 31 31 2e 67 69 74 68 75 62 2e 69 6f 2f 69 64 66 } //1 student7011.github.io/idf
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}