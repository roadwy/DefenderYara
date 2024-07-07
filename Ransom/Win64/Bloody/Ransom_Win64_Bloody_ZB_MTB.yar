
rule Ransom_Win64_Bloody_ZB_MTB{
	meta:
		description = "Ransom:Win64/Bloody.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 00 43 00 52 00 59 00 50 00 54 00 } //1 .CRYPT
		$a_01_1 = {41 6c 6c 20 45 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 63 61 6e 20 62 65 20 72 65 76 65 72 73 65 64 20 74 6f 20 6f 72 69 67 69 6e 61 6c 20 66 6f 72 6d } //1 All Encrypted files can be reversed to original form
		$a_01_2 = {62 6c 30 30 64 79 61 64 6d 69 6e } //1 bl00dyadmin
		$a_01_3 = {49 20 68 61 76 65 20 73 74 6f 6c 65 6e 20 41 6c 6c 20 59 6f 75 72 20 44 61 74 61 62 61 73 65 73 } //1 I have stolen All Your Databases
		$a_01_4 = {41 4c 4c 20 66 69 6c 65 73 20 6f 4e 20 59 6f 75 72 20 45 6e 74 69 72 65 20 4e 65 74 77 6f 72 6b 20 53 65 72 76 65 72 73 20 61 6e 64 20 43 6f 6e 6e 65 63 74 65 64 20 44 65 76 69 63 65 73 20 61 72 65 20 45 6e 63 72 79 70 74 65 64 } //1 ALL files oN Your Entire Network Servers and Connected Devices are Encrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}