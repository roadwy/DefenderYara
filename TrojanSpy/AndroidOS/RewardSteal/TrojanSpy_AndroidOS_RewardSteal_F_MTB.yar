
rule TrojanSpy_AndroidOS_RewardSteal_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RewardSteal.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 69 6d 72 61 6e 68 61 73 6d 69 2e } //05 00 
		$a_01_1 = {63 6f 6d 2f 61 6c 6c 73 65 72 76 69 63 65 63 65 6e 74 65 72 2f 61 6e 64 72 6f 69 64 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_2 = {26 66 72 6f 6d 3d 61 70 70 } //01 00 
		$a_01_3 = {73 65 6e 64 44 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}