
rule Backdoor_Linux_SAgnt_F_MTB{
	meta:
		description = "Backdoor:Linux/SAgnt.F!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 68 6f 6d 65 2f 75 73 65 72 2f 6f 73 73 6c 5f 62 61 63 6b 64 6f 6f 72 2f 62 61 63 6b 64 6f 6f 72 2e 63 } //1 /home/user/ossl_backdoor/backdoor.c
		$a_01_1 = {2f 68 6f 6d 65 2f 75 73 65 72 2f 6f 73 73 6c 5f 62 61 63 6b 64 6f 6f 72 2f 6f 70 65 6e 73 73 6c 2f 64 69 67 65 73 74 63 6f 6d 6d 6f 6e 2e 63 } //1 /home/user/ossl_backdoor/openssl/digestcommon.c
		$a_01_2 = {70 72 6f 76 69 64 65 72 3d 6e 6f 74 5f 61 5f 62 61 63 6b 64 6f 6f 72 } //1 provider=not_a_backdoor
		$a_01_3 = {41 56 49 89 f6 41 55 49 89 d5 41 54 49 89 cc 55 48 89 fd bf 10 00 00 00 53 e8 de fb ff ff 48 89 c3 48 85 c0 74 3d 4c 89 f6 48 89 ef e8 fb fb ff ff 48 89 43 08 48 85 c0 74 22 48 8d 05 cb 25 00 00 49 89 1c 24 48 89 2b 49 89 45 00 b8 01 00 00 00 5b 5d 41 5c 41 5d 41 5e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}