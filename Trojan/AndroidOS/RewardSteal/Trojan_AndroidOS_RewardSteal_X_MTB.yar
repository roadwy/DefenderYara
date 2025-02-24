
rule Trojan_AndroidOS_RewardSteal_X_MTB{
	meta:
		description = "Trojan:AndroidOS/RewardSteal.X!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 03 20 00 6e 20 39 28 31 00 0c 04 1f 04 0d 07 6e 20 40 28 94 00 0a 05 38 05 11 00 } //1
		$a_01_1 = {5b 53 e9 03 22 03 b1 02 70 10 cd 0c 03 00 5b 53 ec 03 5c 51 ed 03 5b 56 d8 03 62 06 49 05 6e 20 85 0c 62 00 62 06 47 05 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}