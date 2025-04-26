
rule Ransom_Win32_Revil_D_MTB{
	meta:
		description = "Ransom:Win32/Revil.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_81_0 = {44 4f 4e 54 20 74 72 79 20 74 6f 20 63 68 61 6e 67 65 20 66 69 6c 65 73 20 62 79 20 79 6f 75 72 73 65 6c 66 2c 20 44 4f 4e 54 20 75 73 65 20 61 6e 79 20 74 68 69 72 64 20 70 61 72 74 79 20 73 6f 66 74 77 61 72 65 20 66 6f 72 20 72 65 73 74 6f 72 69 6e 67 20 79 6f 75 72 20 64 61 74 61 20 6f 72 20 61 6e 74 69 76 69 72 75 73 20 73 6f 6c 75 74 69 6f 6e 73 } //1 DONT try to change files by yourself, DONT use any third party software for restoring your data or antivirus solutions
		$a_81_1 = {49 74 73 20 69 6e 20 79 6f 75 72 20 69 6e 74 65 72 65 73 74 73 20 74 6f 20 67 65 74 20 79 6f 75 72 20 66 69 6c 65 73 20 62 61 63 6b 2e 20 46 72 6f 6d 20 6f 75 72 20 73 69 64 65 2c 20 77 65 20 28 74 68 65 20 62 65 73 74 20 73 70 65 63 69 61 6c 69 73 74 73 29 20 6d 61 6b 65 20 65 76 65 72 79 74 68 69 6e 67 20 66 6f 72 20 72 65 73 74 6f 72 69 6e 67 } //1 Its in your interests to get your files back. From our side, we (the best specialists) make everything for restoring
		$a_81_2 = {4e 6f 77 20 77 69 74 68 20 74 77 69 63 65 20 74 68 65 20 72 61 6e 73 6f 6d 21 } //1 Now with twice the ransom!
		$a_81_3 = {74 61 7a 65 72 66 61 63 65 20 73 74 72 69 6b 65 73 20 61 67 61 69 6e 21 } //1 tazerface strikes again!
		$a_81_4 = {59 6f 75 20 63 61 6e 20 63 68 65 63 6b 20 69 74 3a 20 61 6c 6c 20 66 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 73 79 73 74 65 6d 20 68 61 73 20 65 78 74 65 6e 73 69 6f 6e 20 45 4e 43 52 59 50 54 45 44 } //1 You can check it: all files on your system has extension ENCRYPTED
		$a_81_5 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 2c 20 61 6e 64 20 63 75 72 72 65 6e 74 6c 79 20 75 6e 61 76 61 69 6c 61 62 6c 65 2e } //1 Your files are encrypted, and currently unavailable.
		$a_81_6 = {57 65 20 61 62 73 6f 6c 75 74 65 6c 79 20 64 6f 20 6e 6f 74 20 63 61 72 65 20 61 62 6f 75 74 20 79 6f 75 20 61 6e 64 20 79 6f 75 72 20 64 65 61 6c 73 2c 20 65 78 63 65 70 74 20 67 65 74 74 69 6e 67 20 62 65 6e 65 66 69 74 73 2e } //1 We absolutely do not care about you and your deals, except getting benefits.
		$a_81_7 = {54 68 65 72 65 20 79 6f 75 20 63 61 6e 20 64 65 63 72 79 70 74 20 6f 6e 65 20 66 69 6c 65 20 66 6f 72 20 66 72 65 65 2e 20 54 68 61 74 20 69 73 20 6f 75 72 20 67 75 61 72 61 6e 74 65 65 2e } //1 There you can decrypt one file for free. That is our guarantee.
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=5
 
}