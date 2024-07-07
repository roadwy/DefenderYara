
rule Backdoor_MacOS_GoDoor_A_MTB{
	meta:
		description = "Backdoor:MacOS/GoDoor.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 73 65 6e 64 46 69 6c 65 54 6f 4d 79 74 68 69 63 } //1 main.sendFileToMythic
		$a_01_1 = {47 65 74 46 69 6c 65 46 72 6f 6d 4d 79 74 68 69 63 } //1 GetFileFromMythic
		$a_01_2 = {6d 61 69 6e 2e 61 67 67 72 65 67 61 74 65 44 65 6c 65 67 61 74 65 4d 65 73 73 61 67 65 73 54 6f 4d 79 74 68 69 63 } //1 main.aggregateDelegateMessagesToMythic
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}