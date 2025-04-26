
rule Ransom_Linux_Zamok_A_MTB{
	meta:
		description = "Ransom:Linux/Zamok.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6e 2e 6d 6f 76 65 5f 74 6f 5f 68 6f 6d 65 } //1 main.move_to_home
		$a_00_1 = {7a 61 6d 6f 6b } //1 zamok
		$a_00_2 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 5f 64 69 72 } //1 main.encrypt_dir
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}