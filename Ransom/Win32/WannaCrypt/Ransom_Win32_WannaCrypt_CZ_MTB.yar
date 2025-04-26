
rule Ransom_Win32_WannaCrypt_CZ_MTB{
	meta:
		description = "Ransom:Win32/WannaCrypt.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 48 74 79 44 5a 63 73 72 74 54 34 2f 74 33 4f 2b 33 73 6d 6c 53 43 4f 48 4f 47 50 65 63 44 39 57 79 48 69 4b 39 32 67 36 55 35 79 55 } //1 mHtyDZcsrtT4/t3O+3smlSCOHOGPecD9WyHiK92g6U5yU
		$a_01_1 = {76 67 4c 76 2f 34 43 47 53 57 58 35 43 64 41 59 35 62 56 4f 6d 69 4b 33 55 52 71 4a 47 47 36 4d 43 70 54 43 35 4d 42 } //1 vgLv/4CGSWX5CdAY5bVOmiK3URqJGG6MCpTC5MB
		$a_01_2 = {31 00 37 00 32 00 2e 00 31 00 36 00 2e 00 39 00 39 00 2e 00 35 00 5c 00 49 00 50 00 43 00 24 00 } //1 172.16.99.5\IPC$
		$a_01_3 = {52 70 2f 6f 76 5a 57 65 68 36 35 6a 36 47 35 6d 56 53 33 6f 33 55 78 35 63 48 32 70 66 54 2f 56 5a } //1 Rp/ovZWeh65j6G5mVS3o3Ux5cH2pfT/VZ
		$a_01_4 = {50 6c 61 79 47 61 6d 65 } //1 PlayGame
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}