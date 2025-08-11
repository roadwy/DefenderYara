
rule Ransom_Linux_RAWorld_A_MTB{
	meta:
		description = "Ransom:Linux/RAWorld.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 41 20 57 6f 72 6c 64 } //1 RA World
		$a_01_1 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 46 69 6c 65 } //1 main.encryptFile
		$a_01_2 = {70 61 74 68 2f 66 69 6c 65 70 61 74 68 2e 72 65 61 64 44 69 72 4e 61 6d 65 73 } //1 path/filepath.readDirNames
		$a_03_3 = {74 74 70 3a 2f 2f 72 61 77 6f 72 6c 64 [0-50] 2e 6f 6e 69 6f 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}