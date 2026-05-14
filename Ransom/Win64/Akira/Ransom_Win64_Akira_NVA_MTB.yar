
rule Ransom_Win64_Akira_NVA_MTB{
	meta:
		description = "Ransom:Win64/Akira.NVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {70 6b 63 73 37 2d 73 69 67 6e 65 64 41 6e 64 45 6e 76 65 6c 6f 70 65 64 44 61 74 61 } //1 pkcs7-signedAndEnvelopedData
		$a_81_1 = {70 6b 63 73 37 2d 65 6e 63 72 79 70 74 65 64 44 61 74 61 } //1 pkcs7-encryptedData
		$a_81_2 = {48 45 48 45 4b 45 59 } //1 HEHEKEY
		$a_81_3 = {44 65 73 6b 74 6f 70 5c 52 45 41 44 4d 45 5f 52 45 43 4f 56 45 52 59 2e 74 78 74 } //1 Desktop\README_RECOVERY.txt
		$a_81_4 = {72 65 63 6f 76 65 72 79 5f 73 75 70 70 6f 72 74 40 70 72 6f 74 6f 6e 6d 61 69 6c } //1 recovery_support@protonmail
		$a_81_5 = {55 4e 49 51 55 45 5f 49 44 5f 31 32 33 34 35 36 } //1 UNIQUE_ID_123456
		$a_01_6 = {86 55 20 43 e1 bb a6 41 20 42 e1 ba a0 4e 20 c4 90 c3 83 20 42 e1 bb 8a 20 4d c3 83 20 48 c3 93 41 20 21 21 21 0a 00 00 54 e1 ba a5 74 20 63 e1 ba a3 20 63 c3 a1 63 20 74 e1 bb 87 70 20 71 75 61 6e 20 74 72 e1 bb 8d 6e 67 20 63 e1 bb a7 61 20 62 } //2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_01_6  & 1)*2) >=8
 
}