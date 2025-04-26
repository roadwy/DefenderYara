
rule Ransom_Linux_Locky_A_MTB{
	meta:
		description = "Ransom:Linux/Locky.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 6e 63 72 79 70 74 5f 66 69 6c 65 } //1 encrypt_file
		$a_01_1 = {2e 6f 73 69 72 69 73 } //1 .osiris
		$a_01_2 = {65 6e 63 72 79 70 74 5f 62 6c 6f 63 6b } //1 encrypt_block
		$a_01_3 = {62 79 74 65 5f 74 6f 5f 78 6f 72 20 3d } //1 byte_to_xor =
		$a_01_4 = {52 77 20 62 79 20 5b 61 66 6a 6f 73 65 70 68 5d } //1 Rw by [afjoseph]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}