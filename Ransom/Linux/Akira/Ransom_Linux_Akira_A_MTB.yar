
rule Ransom_Linux_Akira_A_MTB{
	meta:
		description = "Ransom:Linux/Akira.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 6b 69 72 61 5f 72 65 61 64 6d 65 2e 74 78 74 } //1 akira_readme.txt
		$a_01_1 = {2d 2d 65 6e 63 72 79 70 74 69 6f 6e 5f 70 61 74 68 } //1 --encryption_path
		$a_01_2 = {2d 2d 73 68 61 72 65 5f 66 69 6c 65 } //1 --share_file
		$a_01_3 = {2e 61 6b 69 72 61 } //1 .akira
		$a_01_4 = {2d 2d 65 6e 63 72 79 70 74 69 6f 6e 5f 70 65 72 63 65 6e 74 } //1 --encryption_percent
		$a_03_5 = {74 74 70 73 3a 2f 2f [0-58] 2e 6f 6e 69 6f 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}