
rule Ransom_Linux_Babuk_D_MTB{
	meta:
		description = "Ransom:Linux/Babuk.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6e 2e 64 65 63 72 79 70 74 5f 66 69 6c 65 } //1 main.decrypt_file
		$a_00_1 = {66 69 6c 65 70 61 74 68 2e 57 61 6c 6b } //1 filepath.Walk
		$a_00_2 = {67 6f 6c 61 6e 67 2e 6f 72 67 2f 78 2f 63 72 79 70 74 6f 2f 63 68 61 63 68 61 32 30 } //1 golang.org/x/crypto/chacha20
		$a_00_3 = {42 41 42 55 4b 5f 4c 4f 43 4b } //1 BABUK_LOCK
		$a_00_4 = {67 6f 6c 61 6e 67 2e 6f 72 67 2f 78 2f 63 72 79 70 74 6f 2f 63 75 72 76 65 32 35 35 31 39 } //1 golang.org/x/crypto/curve25519
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}