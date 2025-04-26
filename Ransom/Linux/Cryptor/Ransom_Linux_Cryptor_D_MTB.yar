
rule Ransom_Linux_Cryptor_D_MTB{
	meta:
		description = "Ransom:Linux/Cryptor.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 70 61 74 68 2f 74 6f 2f 62 65 2f 65 6e 63 72 79 70 74 65 64 } //1 /path/to/be/encrypted
		$a_01_1 = {2f 2e 62 61 73 68 5f 68 69 73 74 6f 72 79 } //1 /.bash_history
		$a_01_2 = {2e 63 72 59 70 74 } //1 .crYpt
		$a_01_3 = {72 65 61 64 6d 65 5f 66 6f 72 5f 75 6e 6c 6f 63 6b 2e 74 78 74 } //1 readme_for_unlock.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}