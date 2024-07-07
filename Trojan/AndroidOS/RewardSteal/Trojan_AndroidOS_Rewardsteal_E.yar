
rule Trojan_AndroidOS_Rewardsteal_E{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.E,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 63 74 69 76 69 74 79 43 6f 6e 67 72 61 42 69 6e 64 69 6e 67 } //2 ActivityCongraBinding
		$a_01_1 = {73 65 6e 64 53 6d 73 44 61 74 61 54 6f 41 70 69 } //2 sendSmsDataToApi
		$a_01_2 = {6e 61 76 69 67 61 74 65 54 6f 54 65 78 74 53 63 72 65 65 6e 41 66 74 65 72 44 65 6c 61 79 } //2 navigateToTextScreenAfterDelay
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}