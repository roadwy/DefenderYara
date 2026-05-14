
rule Ransom_Win64_Goransom_MKV_MTB{
	meta:
		description = "Ransom:Win64/Goransom.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_81_0 = {71 4f 71 66 77 67 74 76 32 66 53 54 7a 34 42 4a 62 37 77 53 2f 64 59 6c 61 54 71 77 6c 69 39 53 6e 49 31 31 5a 38 77 41 47 2f 77 5a 6e 41 6d 56 2d 56 61 63 38 79 35 67 36 34 56 4c 65 59 2f 55 67 6c 39 68 31 6f 57 6b 50 50 57 4d 4d 79 42 37 78 79 65 } //1 qOqfwgtv2fSTz4BJb7wS/dYlaTqwli9SnI11Z8wAG/wZnAmV-Vac8y5g64VLeY/Ugl9h1oWkPPWMMyB7xye
		$a_81_1 = {65 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //1 encryptionKey
		$a_81_2 = {65 6e 63 72 79 70 74 65 64 44 61 74 61 } //1 encryptedData
		$a_81_3 = {65 6e 63 72 79 70 74 65 64 4d 50 49 31 } //1 encryptedMPI1
		$a_81_4 = {65 6e 63 72 79 70 74 65 64 4d 50 49 32 } //1 encryptedMPI2
		$a_81_5 = {70 61 63 6b 65 74 2e 45 6e 63 72 79 70 74 65 64 4b 65 79 } //1 packet.EncryptedKey
		$a_81_6 = {70 61 63 6b 65 74 2e 6b 64 66 41 6c 67 6f 72 69 74 68 6d } //1 packet.kdfAlgorithm
		$a_81_7 = {6d 61 69 6e 2e 64 65 63 6f 64 65 53 74 72 69 6e 67 } //1 main.decodeString
		$a_81_8 = {6d 61 69 6e 2e 64 65 63 72 79 70 74 46 69 6c 65 2e 66 75 6e 63 31 } //1 main.decryptFile.func1
		$a_81_9 = {6d 61 69 6e 2e 72 65 61 64 6d 65 46 69 6c 65 4e 61 6d 65 } //1 main.readmeFileName
		$a_81_10 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 46 69 6c 65 45 78 74 } //1 main.encryptFileExt
		$a_81_11 = {43 69 70 68 65 72 46 75 6e 63 } //1 CipherFunc
		$a_81_12 = {64 65 63 6f 64 65 48 75 66 66 6d 61 6e } //1 decodeHuffman
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=13
 
}