
rule Ransom_Win64_LockBit_MKC_MTB{
	meta:
		description = "Ransom:Win64/LockBit.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_81_0 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //1 -----BEGIN RSA PUBLIC KEY-----
		$a_81_1 = {2d 2d 2d 2d 2d 45 4e 44 20 52 53 41 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //1 -----END RSA PUBLIC KEY-----
		$a_81_2 = {68 69 6a 61 63 6b 65 64 2e 70 64 62 } //3 hijacked.pdb
		$a_81_3 = {64 65 63 72 79 70 74 69 6f 6e 64 65 73 63 72 69 70 74 69 6f 6e 2e 70 64 66 } //1 decryptiondescription.pdf
		$a_81_4 = {2e 6c 6f 63 6b } //2 .lock
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*3+(#a_81_3  & 1)*1+(#a_81_4  & 1)*2) >=8
 
}