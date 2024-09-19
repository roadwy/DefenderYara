
rule Trojan_AndroidOS_Rewardsteal_FT{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.FT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 68 6f 6e 65 20 4f 52 20 53 4d 53 20 70 65 72 6d 69 73 73 69 6f 6e 20 69 73 20 6e 6f 74 20 67 72 61 6e 74 65 64 } //1 Phone OR SMS permission is not granted
		$a_01_1 = {53 4d 53 20 53 41 56 45 20 54 4f 20 50 41 4e 45 20 3a } //1 SMS SAVE TO PANE :
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}