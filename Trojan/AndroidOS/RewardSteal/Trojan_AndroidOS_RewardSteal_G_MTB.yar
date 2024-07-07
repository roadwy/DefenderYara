
rule Trojan_AndroidOS_RewardSteal_G_MTB{
	meta:
		description = "Trojan:AndroidOS/RewardSteal.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 72 65 77 61 72 64 73 61 70 70 } //1 com.example.rewardsapp
		$a_01_1 = {63 61 72 64 5f 6e 75 6d 62 65 72 } //1 card_number
		$a_01_2 = {73 74 6f 72 65 43 61 72 64 49 6e 66 6f } //1 storeCardInfo
		$a_01_3 = {44 45 56 5f 52 65 77 61 72 64 5f 50 6f 69 6e 74 73 73 } //1 DEV_Reward_Pointss
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}