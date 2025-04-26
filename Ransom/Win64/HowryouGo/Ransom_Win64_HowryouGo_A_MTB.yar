
rule Ransom_Win64_HowryouGo_A_MTB{
	meta:
		description = "Ransom:Win64/HowryouGo.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 5f 6c 69 73 74 } //1 main.encrypt_list
		$a_81_1 = {6d 61 69 6e 2e 47 65 74 46 69 6c 65 73 41 6e 64 44 69 72 73 } //1 main.GetFilesAndDirs
		$a_81_2 = {6d 61 69 6e 2e 77 72 69 74 65 52 65 61 64 4d 65 } //1 main.writeReadMe
		$a_81_3 = {6d 61 69 6e 2e 66 75 63 6b 6f 66 66 } //1 main.fuckoff
		$a_81_4 = {6d 61 69 6e 2e 66 69 6c 65 5f 6e 6f 74 5f 65 6e 63 72 79 70 74 } //1 main.file_not_encrypt
		$a_81_5 = {6d 61 69 6e 2e 62 6c 61 63 6b 5f 6c 69 73 74 5f 65 78 74 } //1 main.black_list_ext
		$a_81_6 = {6d 61 69 6e 2e 77 68 69 74 65 5f 6c 69 73 74 5f 65 78 74 } //1 main.white_list_ext
		$a_81_7 = {6d 61 69 6e 2e 72 65 61 64 5f 6d 65 5f 6e 61 6d 65 } //1 main.read_me_name
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}