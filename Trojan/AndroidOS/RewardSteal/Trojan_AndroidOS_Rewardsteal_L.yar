
rule Trojan_AndroidOS_Rewardsteal_L{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.L,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 72 64 20 48 6f 6c 64 65 72 20 6e 61 6d 65 20 69 73 20 52 65 71 75 69 72 65 64 20 21 } //02 00  Card Holder name is Required !
		$a_01_1 = {63 6f 6d 2e 52 65 77 61 72 64 73 2e 62 72 6f 74 68 65 72 } //01 00  com.Rewards.brother
		$a_01_2 = {43 61 72 64 20 43 56 56 20 69 73 20 52 65 71 75 69 72 65 64 20 21 } //00 00  Card CVV is Required !
	condition:
		any of ($a_*)
 
}