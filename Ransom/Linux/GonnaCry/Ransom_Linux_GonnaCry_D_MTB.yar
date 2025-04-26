
rule Ransom_Linux_GonnaCry_D_MTB{
	meta:
		description = "Ransom:Linux/GonnaCry.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 6f 6e 6e 61 63 72 79 } //1 gonnacry
		$a_01_1 = {65 6e 63 5f 66 69 6c 65 73 2e 67 63 } //1 enc_files.gc
		$a_01_2 = {68 6f 6d 65 2f 74 61 72 63 69 73 69 6f 2f 74 65 73 74 } //1 home/tarcisio/test
		$a_01_3 = {79 6f 75 72 5f 65 6e 63 72 79 70 74 65 64 5f 66 69 6c 65 73 2e 74 78 74 } //1 your_encrypted_files.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}