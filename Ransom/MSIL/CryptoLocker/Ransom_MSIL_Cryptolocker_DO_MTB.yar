
rule Ransom_MSIL_Cryptolocker_DO_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 0c 00 00 "
		
	strings :
		$a_81_0 = {73 69 6d 70 6c 65 2d 72 61 6e 73 6f 6d 77 61 72 65 } //50 simple-ransomware
		$a_81_1 = {79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //50 your files have been encrypted
		$a_81_2 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 } //50 All your files encrypted
		$a_81_3 = {66 69 6c 65 73 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 65 6e 63 72 79 70 74 65 64 } //20 files successfully encrypted
		$a_81_4 = {44 45 43 52 59 50 54 49 4f 4e 5f 4c 4f 47 2e 74 78 74 } //20 DECRYPTION_LOG.txt
		$a_81_5 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //20 vssadmin.exe Delete Shadows /All /Quiet
		$a_81_6 = {2e 63 72 79 70 74 65 64 } //3 .crypted
		$a_81_7 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //3 DisableAntiSpyware
		$a_81_8 = {44 45 43 52 59 50 54 5f 52 65 61 64 4d 65 31 2e 54 58 54 } //3 DECRYPT_ReadMe1.TXT
		$a_81_9 = {45 6e 63 72 79 70 74 46 69 6c 65 53 69 6d 70 6c 65 } //1 EncryptFileSimple
		$a_81_10 = {4e 6f 20 66 69 6c 65 73 20 74 6f 20 65 6e 63 72 79 70 74 } //1 No files to encrypt
		$a_81_11 = {48 75 67 65 4d 65 } //1 HugeMe
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*50+(#a_81_3  & 1)*20+(#a_81_4  & 1)*20+(#a_81_5  & 1)*20+(#a_81_6  & 1)*3+(#a_81_7  & 1)*3+(#a_81_8  & 1)*3+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=74
 
}