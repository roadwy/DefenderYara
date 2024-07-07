
rule TrojanSpy_AndroidOS_RewardSteal_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RewardSteal.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 68 65 61 6b 70 65 72 6d 69 73 73 69 6f 6e } //1 Cheakpermission
		$a_01_1 = {63 61 72 64 4e 75 6d 62 65 72 } //1 cardNumber
		$a_03_2 = {4c 63 6f 6d 2f 72 65 77 61 72 64 73 2f 90 02 04 2f 53 6d 73 52 65 63 65 69 76 65 72 90 00 } //1
		$a_01_3 = {66 69 6e 69 73 68 41 66 66 69 6e 69 74 79 } //1 finishAffinity
		$a_01_4 = {6c 6f 61 64 64 4c 61 73 74 53 63 72 65 65 6e } //1 loaddLastScreen
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}