
rule Ransom_Linux_ECh0raix_B_MTB{
	meta:
		description = "Ransom:Linux/ECh0raix.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 64 65 63 72 79 70 74 54 65 73 74 46 69 6c 65 } //1 main.decryptTestFile
		$a_01_1 = {66 69 6c 65 70 61 74 68 2e 57 61 6c 6b } //1 filepath.Walk
		$a_01_2 = {63 61 6e 57 72 69 74 65 52 65 63 6f 72 64 } //1 canWriteRecord
		$a_01_3 = {64 69 72 74 79 4c 6f 63 6b 65 64 } //1 dirtyLocked
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}