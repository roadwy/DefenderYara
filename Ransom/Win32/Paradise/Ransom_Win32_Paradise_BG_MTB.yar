
rule Ransom_Win32_Paradise_BG_MTB{
	meta:
		description = "Ransom:Win32/Paradise.BG!MTB,SIGNATURE_TYPE_PEHSTR,1e 00 16 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6f 20 6e 6f 74 20 72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //01 00  Do not rename encrypted files
		$a_01_1 = {57 48 41 54 20 48 41 50 50 45 4e 45 44 21 } //01 00  WHAT HAPPENED!
		$a_01_2 = {74 00 61 00 72 00 69 00 64 00 64 00 } //0a 00  taridd
		$a_01_3 = {46 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 70 63 20 77 65 72 65 20 65 6e 63 6f 64 65 64 } //01 00  Files on your pc were encoded
		$a_01_4 = {4f 00 50 00 45 00 4e 00 5f 00 4d 00 45 00 5f 00 55 00 50 00 } //0a 00  OPEN_ME_UP
		$a_01_5 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 77 00 61 00 72 00 65 00 } //0a 00  DisableAntiSpyware
		$a_01_6 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //00 00  delete shadows /all /quiet
		$a_01_7 = {00 5d 04 00 00 f9 46 04 80 5c 26 00 00 fa } //46 04 
	condition:
		any of ($a_*)
 
}