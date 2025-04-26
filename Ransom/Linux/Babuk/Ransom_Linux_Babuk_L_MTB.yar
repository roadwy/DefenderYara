
rule Ransom_Linux_Babuk_L_MTB{
	meta:
		description = "Ransom:Linux/Babuk.L!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 62 61 62 79 6b } //1 .babyk
		$a_01_1 = {4b 69 6c 6c 56 4d } //1 KillVM
		$a_01_2 = {76 6d 2d 6c 69 73 74 2e 74 78 74 } //1 vm-list.txt
		$a_01_3 = {45 6e 63 72 79 70 74 69 6e 67 3a } //1 Encrypting:
		$a_01_4 = {2f 52 45 41 44 4d 45 5f 54 4f 5f 52 45 53 54 4f 52 45 2e 74 78 74 } //1 /README_TO_RESTORE.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}