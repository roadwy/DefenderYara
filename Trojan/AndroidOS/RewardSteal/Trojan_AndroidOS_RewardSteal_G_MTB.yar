
rule Trojan_AndroidOS_RewardSteal_G_MTB{
	meta:
		description = "Trojan:AndroidOS/RewardSteal.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 72 65 77 61 72 64 73 61 70 70 } //01 00 
		$a_01_1 = {63 61 72 64 5f 6e 75 6d 62 65 72 } //01 00 
		$a_01_2 = {73 74 6f 72 65 43 61 72 64 49 6e 66 6f } //01 00 
		$a_01_3 = {44 45 56 5f 52 65 77 61 72 64 5f 50 6f 69 6e 74 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}