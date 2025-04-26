
rule Ransom_MSIL_Cryptolocker_ED_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 0e 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 } //50 Your computer has been infected
		$a_81_1 = {4a 61 73 6d 69 6e 5f 45 6e 63 72 79 70 74 65 72 } //50 Jasmin_Encrypter
		$a_81_2 = {4a 61 6e 75 73 4c 6f 63 6b 65 72 } //50 JanusLocker
		$a_81_3 = {2e 72 73 6a 6f 6e } //50 .rsjon
		$a_81_4 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //20 @protonmail.com
		$a_81_5 = {2e 6a 61 73 6d 69 6e } //20 .jasmin
		$a_81_6 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //3 vssadmin delete shadows /all /quiet
		$a_81_7 = {75 6e 6c 6f 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 } //3 unlock your files
		$a_81_8 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //3 Your personal files are encrypted
		$a_81_9 = {70 72 6f 6f 66 20 6f 66 20 70 61 79 6d 65 6e 74 20 6c 69 6b 65 20 73 68 69 74 } //3 proof of payment like shit
		$a_81_10 = {42 54 43 20 54 4f 20 54 48 49 53 20 57 41 4c 4c 45 54 3a } //1 BTC TO THIS WALLET:
		$a_81_11 = {65 72 72 6f 72 20 68 61 20 62 68 61 69 79 61 } //1 error ha bhaiya
		$a_81_12 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 4c 69 73 74 } //1 EncryptedFilesList
		$a_81_13 = {52 45 41 44 5f 4d 45 5f 50 4c 5a 2e 74 78 74 } //1 READ_ME_PLZ.txt
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*50+(#a_81_3  & 1)*50+(#a_81_4  & 1)*20+(#a_81_5  & 1)*20+(#a_81_6  & 1)*3+(#a_81_7  & 1)*3+(#a_81_8  & 1)*3+(#a_81_9  & 1)*3+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=74
 
}