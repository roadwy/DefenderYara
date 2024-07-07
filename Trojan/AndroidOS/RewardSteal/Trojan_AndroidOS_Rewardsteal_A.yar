
rule Trojan_AndroidOS_Rewardsteal_A{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {72 65 77 61 72 64 73 2f 52 65 73 74 61 72 74 65 72 3b } //1 rewards/Restarter;
		$a_01_1 = {4d 6f 6e 74 68 20 6d 75 73 74 20 62 65 20 62 65 6c 6f 77 20 31 32 } //1 Month must be below 12
		$a_01_2 = {43 56 56 20 6d 75 73 74 20 62 65 20 6f 66 20 33 20 64 69 67 69 74 73 2e } //1 CVV must be of 3 digits.
		$a_01_3 = {40 6c 75 63 6b 79 2e 63 6f 6d } //1 @lucky.com
		$a_01_4 = {72 65 77 61 72 64 73 2f 59 6f 75 72 53 65 72 76 69 63 65 3b } //1 rewards/YourService;
		$a_01_5 = {59 65 61 72 20 6d 75 73 74 20 62 65 20 6c 65 73 73 20 74 68 61 6e 20 32 30 31 30 2e } //1 Year must be less than 2010.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}