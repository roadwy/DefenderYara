
rule Ransom_Win64_Mallox_AMAA_MTB{
	meta:
		description = "Ransom:Win64/Mallox.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {59 6f 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //Your data has been stolen and encrypted  1
		$a_80_1 = {57 65 20 77 69 6c 6c 20 64 65 6c 65 74 65 20 74 68 65 20 73 74 6f 6c 65 6e 20 64 61 74 61 20 61 6e 64 20 68 65 6c 70 20 77 69 74 68 20 74 68 65 20 72 65 63 6f 76 65 72 79 20 6f 66 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 61 66 74 65 72 20 70 61 79 6d 65 6e 74 20 68 61 73 20 62 65 65 6e 20 6d 61 64 65 } //We will delete the stolen data and help with the recovery of encrypted files after payment has been made  1
		$a_80_2 = {77 74 79 61 66 6a 79 68 77 71 72 67 6f 34 61 34 35 77 64 76 76 77 68 65 6e 33 63 78 34 65 75 69 65 37 33 71 76 6c 68 6b 68 76 6c 72 65 78 6c 6a 6f 79 75 6b 6c 61 61 64 2e 6f 6e 69 6f 6e } //wtyafjyhwqrgo4a45wdvvwhen3cx4euie73qvlhkhvlrexljoyuklaad.onion  1
		$a_80_3 = {48 4f 57 20 54 4f 20 42 41 43 4b 20 46 49 4c 45 53 2e 74 78 74 } //HOW TO BACK FILES.txt  1
		$a_80_4 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //delete shadows /all /quiet  1
		$a_80_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 50 6f 6c 69 63 79 4d 61 6e 61 67 65 72 5c 64 65 66 61 75 6c 74 5c 53 74 61 72 74 5c 48 69 64 65 52 65 73 74 61 72 74 } //SOFTWARE\Microsoft\PolicyManager\default\Start\HideRestart  1
		$a_80_6 = {2e 6d 61 6c 6c 6f 78 } //.mallox  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}