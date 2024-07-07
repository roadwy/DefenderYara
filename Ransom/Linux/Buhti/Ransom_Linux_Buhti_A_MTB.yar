
rule Ransom_Linux_Buhti_A_MTB{
	meta:
		description = "Ransom:Linux/Buhti.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 5f 66 69 6c 65 } //1 main.encrypt_file
		$a_01_1 = {62 75 68 74 69 52 61 6e 73 6f 6d } //1 buhtiRansom
		$a_01_2 = {66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 files are encrypted
		$a_01_3 = {72 65 73 74 6f 72 65 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 } //1 restore all your files
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}