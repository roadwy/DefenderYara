
rule Ransom_MSIL_FileCryptor_DSA_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_81_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //2 taskkill /f /im explorer.exe
		$a_81_1 = {43 6f 72 6f 6e 61 43 72 79 70 74 30 72 } //1 CoronaCrypt0r
		$a_81_2 = {43 6f 62 72 61 5f 4c 6f 63 6b 65 72 } //1 Cobra_Locker
		$a_81_3 = {49 20 68 61 76 65 20 65 6e 63 72 79 70 74 65 64 20 61 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 } //1 I have encrypted all your important files
		$a_81_4 = {54 68 65 72 65 20 69 73 20 6e 6f 20 77 61 79 20 74 6f 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 20 73 6f 72 72 79 } //1 There is no way to recover your files sorry
		$a_81_5 = {43 6f 62 72 61 5f 4c 6f 63 6b 65 72 5f 49 73 5f 54 68 65 5f 42 65 73 74 } //1 Cobra_Locker_Is_The_Best
		$a_81_6 = {61 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 all your important files have been encrypted
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=3
 
}