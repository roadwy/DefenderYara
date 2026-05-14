
rule Ransom_Win32_Akira_DA_MTB{
	meta:
		description = "Ransom:Win32/Akira.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_81_0 = {61 6b 69 72 61 5f 72 65 61 64 6d 65 2e 74 78 74 } //10 akira_readme.txt
		$a_81_1 = {2e 61 6b 69 72 61 } //10 .akira
		$a_81_2 = {43 69 70 68 65 72 20 64 6f 6e 74 20 73 74 61 72 74 21 } //1 Cipher dont start!
		$a_81_3 = {44 65 63 72 79 70 74 20 65 78 63 65 70 74 69 6f 6e 3a } //1 Decrypt exception:
		$a_81_4 = {2d 2d 65 6e 63 72 79 70 74 69 6f 6e 5f 70 61 74 68 } //1 --encryption_path
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=23
 
}