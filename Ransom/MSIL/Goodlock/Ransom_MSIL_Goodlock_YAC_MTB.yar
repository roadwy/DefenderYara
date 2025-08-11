
rule Ransom_MSIL_Goodlock_YAC_MTB{
	meta:
		description = "Ransom:MSIL/Goodlock.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_01_0 = {47 6f 6f 64 4c 6f 63 6b 2e 65 78 65 } //1 GoodLock.exe
		$a_01_1 = {47 6f 6f 64 4c 6f 63 6b 2e 49 6e 66 6f 2e 72 65 73 6f 75 72 63 65 73 } //1 GoodLock.Info.resources
		$a_01_2 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {44 65 63 72 79 70 74 41 6c 6c 45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } //1 DecryptAllEncryptedFiles
		$a_01_5 = {45 4e 43 52 59 50 54 5f 44 45 53 4b 54 4f 50 } //1 ENCRYPT_DESKTOP
		$a_01_6 = {45 4e 43 52 59 50 54 5f 50 49 43 54 55 52 45 53 } //2 ENCRYPT_PICTURES
		$a_01_7 = {62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 67 00 6f 00 6f 00 64 00 } //10 been encrypted by good
		$a_01_8 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 47 00 6f 00 6f 00 64 00 4c 00 6f 00 63 00 6b } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10) >=18
 
}