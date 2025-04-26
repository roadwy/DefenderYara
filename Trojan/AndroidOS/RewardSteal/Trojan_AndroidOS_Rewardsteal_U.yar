
rule Trojan_AndroidOS_Rewardsteal_U{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.U,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 75 73 68 53 6d 73 44 61 74 61 54 6f 46 69 72 65 62 61 73 65 } //2 pushSmsDataToFirebase
		$a_01_1 = {73 61 76 65 45 6e 64 54 69 6d 65 50 6c 75 73 37 32 48 6f 75 72 73 } //2 saveEndTimePlus72Hours
		$a_01_2 = {76 61 6c 69 64 61 74 65 50 68 6f 6e 65 4e 75 6d 62 65 72 41 6e 64 53 75 62 6d 69 74 } //2 validatePhoneNumberAndSubmit
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}