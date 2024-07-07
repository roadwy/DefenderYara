
rule Trojan_AndroidOS_RewardSteal_F_MTB{
	meta:
		description = "Trojan:AndroidOS/RewardSteal.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 69 6e 2f 72 65 77 61 72 64 } //1 com/in/reward
		$a_00_1 = {72 65 77 61 72 64 73 2f 52 65 73 74 61 72 74 65 72 } //1 rewards/Restarter
		$a_00_2 = {72 65 77 61 72 64 73 2f 59 6f 75 72 53 65 72 76 69 63 65 } //1 rewards/YourService
		$a_00_3 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 } //1 content://sms
		$a_00_4 = {64 65 6c 69 76 65 72 73 65 6c 66 6e 6f 74 69 66 69 63 61 74 69 6f 6e 73 } //1 deliverselfnotifications
		$a_00_5 = {43 56 56 20 6d 75 73 74 20 62 65 20 6f 66 20 33 20 64 69 67 69 74 73 2e } //1 CVV must be of 3 digits.
		$a_00_6 = {40 6c 75 63 6b 79 2e 63 6f 6d } //1 @lucky.com
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=4
 
}