
rule Trojan_AndroidOS_Rewardsteal_V{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.V,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 74 6d 20 34 20 64 69 67 69 74 20 69 73 20 72 65 71 75 69 72 65 64 } //2 atm 4 digit is required
		$a_01_1 = {44 65 62 69 74 43 61 72 64 49 6e 70 75 74 4d 61 73 6b } //2 DebitCardInputMask
		$a_01_2 = {43 56 56 20 33 20 64 69 67 69 74 20 72 65 71 75 69 72 65 64 } //2 CVV 3 digit required
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}