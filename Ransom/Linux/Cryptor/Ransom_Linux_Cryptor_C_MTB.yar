
rule Ransom_Linux_Cryptor_C_MTB{
	meta:
		description = "Ransom:Linux/Cryptor.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2e 65 6e 63 72 79 70 74 65 64 } //2 .encrypted
		$a_02_1 = {2e 2f 72 65 61 64 6d 65 [0-05] 2e 63 72 79 70 74 6f } //2
		$a_00_2 = {2e 2f 69 6e 64 65 78 2e 63 72 79 70 74 6f } //1 ./index.crypto
		$a_00_3 = {53 74 61 72 74 20 65 6e 63 72 79 70 74 69 6e 67 } //1 Start encrypting
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}