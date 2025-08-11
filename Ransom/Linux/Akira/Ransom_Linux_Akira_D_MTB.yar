
rule Ransom_Linux_Akira_D_MTB{
	meta:
		description = "Ransom:Linux/Akira.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 6b 69 72 61 5f 72 65 61 64 6d 65 2e 74 78 74 } //1 akira_readme.txt
		$a_01_1 = {2e 61 6b 69 72 61 } //1 .akira
		$a_01_2 = {2d 2d 73 68 61 72 65 5f 66 69 6c 65 } //1 --share_file
		$a_01_3 = {2e 61 72 69 6b 61 } //1 .arika
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}