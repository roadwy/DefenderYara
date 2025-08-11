
rule Ransom_Linux_Gunra_A_MTB{
	meta:
		description = "Ransom:Linux/Gunra.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 70 61 77 6e 5f 6f 72 5f 77 61 69 74 5f 74 68 72 65 61 64 } //1 spawn_or_wait_thread
		$a_01_1 = {65 6e 63 72 79 70 74 5f 66 69 6c 65 73 5f 74 68 72 65 61 64 } //1 encrypt_files_thread
		$a_01_2 = {25 73 2f 25 73 2e 6b 65 79 73 74 6f 72 65 } //1 %s/%s.keystore
		$a_01_3 = {52 33 41 44 4d 33 2e 74 78 74 } //1 R3ADM3.txt
		$a_01_4 = {48 8b 85 10 ef ff ff 8b b0 0c 10 00 00 48 8b 85 10 ef ff ff 48 8d b8 00 04 00 00 48 8b 85 10 ef ff ff 48 8d 88 00 08 00 00 48 8b 85 10 ef ff ff 8b 90 08 10 00 00 48 8b 85 18 ef ff ff 41 89 f1 49 89 f8 48 89 c6 48 8d 05 43 3b 01 00 48 89 c7 b8 00 00 00 00 e8 46 8b 00 00 48 8b 95 18 ef ff ff 48 8d 85 60 fe ff ff 48 89 d1 48 8d 15 5d 3b 01 00 be 00 01 00 00 48 89 c7 b8 00 00 00 00 e8 fc 8d 00 00 48 8d 85 60 fe ff ff 48 89 45 f8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}