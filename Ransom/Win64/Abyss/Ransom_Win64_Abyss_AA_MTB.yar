
rule Ransom_Win64_Abyss_AA_MTB{
	meta:
		description = "Ransom:Win64/Abyss.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {2e 00 6c 00 6f 00 63 00 6b 00 } //1 .lock
		$a_01_1 = {2e 00 41 00 62 00 79 00 73 00 73 00 } //1 .Abyss
		$a_01_2 = {57 00 68 00 61 00 74 00 48 00 61 00 70 00 70 00 65 00 6e 00 65 00 64 00 2e 00 74 00 78 00 74 00 } //1 WhatHappened.txt
		$a_01_3 = {6b 00 65 00 79 00 2e 00 70 00 75 00 62 00 } //1 key.pub
		$a_01_4 = {77 65 20 77 69 6c 6c 20 70 65 72 6d 61 6e 65 6e 74 6c 79 20 64 65 6c 65 74 65 20 61 6c 6c 20 79 6f 75 72 20 64 61 74 61 20 66 72 6f 6d 20 6f 75 72 20 73 65 72 76 65 72 73 } //1 we will permanently delete all your data from our servers
		$a_01_5 = {70 61 79 6d 65 6e 74 20 61 6e 64 20 64 65 63 72 79 70 74 69 6f 6e } //1 payment and decryption
		$a_01_6 = {57 65 20 61 72 65 20 74 68 65 20 41 62 79 73 73 } //1 We are the Abyss
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}