
rule Ransom_MSIL_GlobeImposter_E_MTB{
	meta:
		description = "Ransom:MSIL/GlobeImposter.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {4c 6f 63 6b 42 69 74 20 42 6c 61 63 6b } //1 LockBit Black
		$a_81_1 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 21 } //1 All your important files are stolen and encrypted!
		$a_81_2 = {52 45 41 44 4d 45 2e 74 78 74 20 66 69 6c 65 } //1 README.txt file
		$a_81_3 = {61 6e 64 20 66 6f 6c 6c 6f 77 20 74 68 65 20 69 6e 73 74 72 75 63 74 69 6f 6e 21 } //1 and follow the instruction!
		$a_81_4 = {7b 30 7d 5c 68 6f 77 5f 74 6f 5f 62 61 63 6b 5f 66 69 6c 65 73 2e 68 74 6d 6c } //1 {0}\how_to_back_files.html
		$a_81_5 = {7b 30 7d 5c 57 61 6c 6c 50 61 70 65 72 2e 62 6d 70 } //1 {0}\WallPaper.bmp
		$a_81_6 = {59 4f 55 52 20 43 4f 4d 50 41 4e 59 20 4e 45 54 57 4f 52 4b 20 48 41 53 20 42 45 45 4e 20 50 45 4e 45 54 52 41 54 45 44 } //1 YOUR COMPANY NETWORK HAS BEEN PENETRATED
		$a_81_7 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 73 61 66 65 21 20 4f 6e 6c 79 20 6d 6f 64 69 66 69 65 64 2e } //1 Your files are safe! Only modified.
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}