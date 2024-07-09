
rule Ransom_Win32_Xorist_SU_MTB{
	meta:
		description = "Ransom:Win32/Xorist.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_81_0 = {30 70 33 6e 53 4f 75 72 63 33 20 58 30 72 31 35 37 } //1 0p3nSOurc3 X0r157
		$a_81_1 = {6d 6f 74 68 65 72 66 75 63 6b 65 72 21 } //1 motherfucker!
		$a_81_2 = {70 75 73 73 79 6c 69 63 6b 65 72 } //1 pussylicker
		$a_81_3 = {48 4f 57 20 54 4f 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 2e 74 78 74 } //1 HOW TO DECRYPT FILES.txt
		$a_81_4 = {41 74 74 65 6e 74 69 6f 6e 21 20 41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //1 Attention! All your files were encrypted!
		$a_81_5 = {59 6f 75 20 68 61 76 65 20 72 65 61 63 68 65 64 20 61 20 6c 69 6d 69 74 20 6f 66 20 61 74 74 65 6d 70 74 73 20 2d 20 79 6f 75 72 20 64 61 74 61 20 69 73 20 69 72 72 65 76 6f 63 61 62 6c 79 20 62 72 6f 6b 65 6e 2e } //1 You have reached a limit of attempts - your data is irrevocably broken.
		$a_03_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-06] 41 6c 63 6d 65 74 65 72 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_03_6  & 1)*1) >=6
 
}