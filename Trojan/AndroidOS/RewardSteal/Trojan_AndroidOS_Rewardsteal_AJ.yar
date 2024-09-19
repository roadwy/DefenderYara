
rule Trojan_AndroidOS_Rewardsteal_AJ{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.AJ,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 73 6b 5f 74 6f 5f 49 67 6e 6f 72 65 5f 62 61 74 74 65 72 79 5f 6f 70 74 69 6d 69 73 61 74 69 6f 6e 73 } //2 Ask_to_Ignore_battery_optimisations
		$a_01_1 = {44 41 54 41 5f 55 53 45 52 5f 4e 4f 57 } //2 DATA_USER_NOW
		$a_01_2 = {50 6f 73 74 44 61 74 61 4e 6f 64 65 43 61 72 64 } //2 PostDataNodeCard
		$a_01_3 = {47 65 74 49 6e 42 6f 78 4d 53 47 5f 46 69 6c 74 65 72 5f 73 70 65 6e 74 } //2 GetInBoxMSG_Filter_spent
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}