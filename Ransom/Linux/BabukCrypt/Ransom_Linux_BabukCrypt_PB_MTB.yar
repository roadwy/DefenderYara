
rule Ransom_Linux_BabukCrypt_PB_MTB{
	meta:
		description = "Ransom:Linux/BabukCrypt.PB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 } //1 main.encrypt
		$a_01_1 = {66 69 6c 65 70 61 74 68 2e 57 61 6c 6b } //1 filepath.Walk
		$a_01_2 = {63 72 79 70 74 6f 2f 63 68 61 63 68 61 32 30 } //1 crypto/chacha20
		$a_01_3 = {42 41 42 55 4b 5f 4c 4f 43 4b 5f 63 75 72 76 65 32 35 35 31 39 } //1 BABUK_LOCK_curve25519
		$a_01_4 = {2f 73 79 73 2f 6b 65 72 6e 65 6c 2f 6d 6d 2f 74 72 61 6e 73 70 61 72 65 6e 74 5f 68 75 67 65 70 61 67 65 2f 68 70 61 67 65 5f 70 6d 64 5f 73 69 7a 65 } //1 /sys/kernel/mm/transparent_hugepage/hpage_pmd_size
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}