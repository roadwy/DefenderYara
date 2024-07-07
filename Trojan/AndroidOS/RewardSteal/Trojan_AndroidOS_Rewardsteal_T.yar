
rule Trojan_AndroidOS_Rewardsteal_T{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.T,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 73 43 72 65 64 69 74 43 61 72 64 56 61 6c 69 64 24 70 61 73 73 65 73 4c 75 68 6e 41 6c 67 6f 72 69 74 68 6d } //1 isCreditCardValid$passesLuhnAlgorithm
		$a_01_1 = {61 63 63 65 73 73 24 6e 61 76 69 67 61 74 65 54 6f 54 65 78 74 53 63 72 65 65 6e 41 66 74 65 72 44 65 6c 61 79 } //1 access$navigateToTextScreenAfterDelay
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}