
rule Ransom_Win32_Encoder_NE_MTB{
	meta:
		description = "Ransom:Win32/Encoder.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 41 4e 53 4f 4d 57 41 52 45 20 53 49 4d 55 4c 41 54 4f 52 20 2d 20 45 4e 43 52 59 50 54 4f 52 } //3 RANSOMWARE SIMULATOR - ENCRYPTOR
		$a_01_1 = {45 4e 43 52 59 50 54 49 4f 4e 20 43 4f 4d 50 4c 45 54 45 } //1 ENCRYPTION COMPLETE
		$a_01_2 = {70 61 73 73 77 6f 72 64 31 32 33 45 6e 63 72 79 70 74 65 64 } //1 password123Encrypted
		$a_01_3 = {65 6e 63 72 79 70 74 6f 72 2e 65 78 65 64 65 63 72 79 70 74 6f 72 2e 65 78 65 } //1 encryptor.exedecryptor.exe
		$a_01_4 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 All your files have been encrypted
		$a_01_5 = {54 6f 20 64 65 63 72 79 70 74 2c 20 75 73 65 20 74 68 65 20 64 65 63 72 79 70 74 6f 72 20 77 69 74 68 20 70 61 73 73 77 6f 72 64 } //1 To decrypt, use the decryptor with password
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}