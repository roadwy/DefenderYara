
rule Ransom_Win32_Paradise_BG_MTB{
	meta:
		description = "Ransom:Win32/Paradise.BG!MTB,SIGNATURE_TYPE_PEHSTR,1e 00 16 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 6f 20 6e 6f 74 20 72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 Do not rename encrypted files
		$a_01_1 = {57 48 41 54 20 48 41 50 50 45 4e 45 44 21 } //1 WHAT HAPPENED!
		$a_01_2 = {74 00 61 00 72 00 69 00 64 00 64 00 } //1 taridd
		$a_01_3 = {46 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 70 63 20 77 65 72 65 20 65 6e 63 6f 64 65 64 } //10 Files on your pc were encoded
		$a_01_4 = {4f 00 50 00 45 00 4e 00 5f 00 4d 00 45 00 5f 00 55 00 50 00 } //1 OPEN_ME_UP
		$a_01_5 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 77 00 61 00 72 00 65 00 } //10 DisableAntiSpyware
		$a_01_6 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //10 delete shadows /all /quiet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10) >=22
 
}