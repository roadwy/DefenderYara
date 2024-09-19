
rule Ransom_Linux_Babuk_J_MTB{
	meta:
		description = "Ransom:Linux/Babuk.J!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 5f 66 69 6c 65 5f 66 75 6c 6c } //1 main.encrypt_file_full
		$a_01_1 = {44 41 54 41 46 20 4c 2a 2a 4f 43 4b 45 52 } //1 DATAF L**OCKER
		$a_01_2 = {68 61 63 6b 20 74 6f 20 6d 61 69 6e 73 74 72 65 61 6d } //1 hack to mainstream
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}