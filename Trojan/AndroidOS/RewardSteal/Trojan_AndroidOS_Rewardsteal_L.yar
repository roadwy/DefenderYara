
rule Trojan_AndroidOS_Rewardsteal_L{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.L,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 61 72 64 20 48 6f 6c 64 65 72 20 6e 61 6d 65 20 69 73 20 52 65 71 75 69 72 65 64 20 21 } //1 Card Holder name is Required !
		$a_01_1 = {63 6f 6d 2e 52 65 77 61 72 64 73 2e 62 72 6f 74 68 65 72 } //2 com.Rewards.brother
		$a_01_2 = {43 61 72 64 20 43 56 56 20 69 73 20 52 65 71 75 69 72 65 64 20 21 } //1 Card CVV is Required !
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_AndroidOS_Rewardsteal_L_2{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.L,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 6d 61 6b 65 77 69 6e 6c 6f 76 65 2e 69 6e 2f } //1 https://makewinlove.in/
		$a_01_1 = {43 61 72 64 20 43 56 56 20 69 73 20 52 65 71 75 69 72 65 64 20 21 } //1 Card CVV is Required !
		$a_01_2 = {4c 63 6f 6d 2f 73 75 70 65 72 63 65 6c 6c 2f 63 6c 61 73 68 6f 66 63 6c 61 6e 2f 54 71 41 63 74 69 76 69 74 79 3b } //1 Lcom/supercell/clashofclan/TqActivity;
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}