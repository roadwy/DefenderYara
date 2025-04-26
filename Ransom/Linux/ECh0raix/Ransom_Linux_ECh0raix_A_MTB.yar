
rule Ransom_Linux_ECh0raix_A_MTB{
	meta:
		description = "Ransom:Linux/ECh0raix.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 77 72 69 74 65 6d 65 73 73 61 67 65 } //1 main.writemessage
		$a_01_1 = {67 6f 6c 61 6e 67 2e 6f 72 67 2f 78 2f 63 72 79 70 74 6f 2f 63 75 72 76 65 32 35 35 31 39 } //1 golang.org/x/crypto/curve25519
		$a_01_2 = {4b 65 79 4c 6f 67 57 72 69 74 65 72 } //1 KeyLogWriter
		$a_01_3 = {66 69 6c 65 70 61 74 68 2e 57 61 6c 6b } //1 filepath.Walk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}