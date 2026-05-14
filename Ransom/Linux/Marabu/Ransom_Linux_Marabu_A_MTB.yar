
rule Ransom_Linux_Marabu_A_MTB{
	meta:
		description = "Ransom:Linux/Marabu.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 5f 72 61 6e 73 6f 6d 5f 6e 6f 74 65 } //1 create_ransom_note
		$a_01_1 = {65 6e 63 72 79 70 74 5f 66 69 6c 65 } //1 encrypt_file
		$a_01_2 = {2e 6d 61 72 61 62 75 } //1 .marabu
		$a_01_3 = {52 45 41 44 5f 54 48 49 53 5f 4e 4f 54 45 2e 74 78 74 } //1 READ_THIS_NOTE.txt
		$a_01_4 = {73 65 63 75 72 65 5f 72 65 6d 6f 76 65 5f 66 69 6c 65 } //1 secure_remove_file
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}