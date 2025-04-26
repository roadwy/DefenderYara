
rule Ransom_Linux_Ransomhub_A{
	meta:
		description = "Ransom:Linux/Ransomhub.A,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 6c 65 61 73 65 20 77 61 69 74 20 66 6f 72 20 74 68 65 20 73 69 6e 67 6c 65 20 66 69 6c 65 20 65 6e 63 72 79 70 74 69 6f 6e 20 74 6f 20 63 6f 6d 70 6c 65 74 65 } //1 please wait for the single file encryption to complete
		$a_00_1 = {75 6e 61 62 6c 65 20 74 6f 20 65 6e 63 72 79 70 74 20 66 69 6c 65 20 25 73 2c 20 74 68 65 20 66 69 6c 65 20 6d 61 79 20 62 65 20 65 6d 70 74 79 } //1 unable to encrypt file %s, the file may be empty
		$a_00_2 = {6d 69 73 73 69 6e 67 20 76 61 6c 75 65 20 66 6f 72 20 2d 70 61 73 73 } //1 missing value for -pass
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}