
rule Trojan_Win64_Amadey_A_MTB{
	meta:
		description = "Trojan:Win64/Amadey.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //2 encryptedUsername
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //2 encryptedPassword
		$a_01_2 = {6e 65 74 73 68 20 77 6c 61 6e 20 65 78 70 6f 72 74 20 70 72 6f 66 69 6c 65 20 6e 61 6d 65 } //2 netsh wlan export profile name
		$a_01_3 = {6e 65 74 73 68 20 77 6c 61 6e 20 73 68 6f 77 20 70 72 6f 66 69 6c 65 73 } //2 netsh wlan show profiles
		$a_01_4 = {68 6f 73 74 6e 61 6d 65 } //2 hostname
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}