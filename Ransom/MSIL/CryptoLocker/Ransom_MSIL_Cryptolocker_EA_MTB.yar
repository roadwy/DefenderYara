
rule Ransom_MSIL_Cryptolocker_EA_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 0f 00 00 "
		
	strings :
		$a_81_0 = {2e 70 61 6c 65 73 74 69 6e 65 } //50 .palestine
		$a_81_1 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //50 All of your files have been encrypted
		$a_81_2 = {52 61 73 6f 6d 77 61 72 65 32 2e 30 } //50 Rasomware2.0
		$a_81_3 = {68 69 64 64 65 6e 2d 74 65 61 72 } //50 hidden-tear
		$a_81_4 = {65 72 61 77 6f 73 6e 61 72 } //20 erawosnar
		$a_81_5 = {72 65 61 64 5f 69 74 2e 74 78 74 } //20 read_it.txt
		$a_81_6 = {5f 45 6e 63 72 79 70 74 65 64 24 } //20 _Encrypted$
		$a_81_7 = {55 72 46 69 6c 65 2e 54 58 54 } //3 UrFile.TXT
		$a_81_8 = {45 6e 63 79 70 74 65 64 4b 65 79 } //3 EncyptedKey
		$a_81_9 = {53 32 46 7a 63 47 56 79 63 32 74 35 4a 51 3d 3d } //3 S2FzcGVyc2t5JQ==
		$a_81_10 = {61 47 6c 6b 5a 47 56 75 4c 58 52 6c 59 58 49 6c } //3 aGlkZGVuLXRlYXIl
		$a_81_11 = {6c 6f 6c 69 70 6f 70 } //1 lolipop
		$a_81_12 = {65 6e 63 72 79 70 74 65 64 46 69 6c 65 45 78 74 65 6e 73 69 6f 6e } //1 encryptedFileExtension
		$a_81_13 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
		$a_81_14 = {4a 6f 68 6e 44 6f 65 } //1 JohnDoe
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*50+(#a_81_3  & 1)*50+(#a_81_4  & 1)*20+(#a_81_5  & 1)*20+(#a_81_6  & 1)*20+(#a_81_7  & 1)*3+(#a_81_8  & 1)*3+(#a_81_9  & 1)*3+(#a_81_10  & 1)*3+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1) >=74
 
}