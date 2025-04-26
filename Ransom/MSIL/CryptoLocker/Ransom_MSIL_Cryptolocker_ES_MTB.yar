
rule Ransom_MSIL_Cryptolocker_ES_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 0c 00 00 "
		
	strings :
		$a_81_0 = {65 72 61 77 6f 73 6e 61 72 } //50 erawosnar
		$a_81_1 = {53 69 6c 76 65 72 20 45 6e 63 72 79 70 74 6f 72 } //50 Silver Encryptor
		$a_81_2 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 6d 75 73 69 63 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //50 All of your music has been encrypted
		$a_81_3 = {6b 69 6c 6c 65 72 40 6b 69 6c 6c 65 72 63 6f 6d } //20 killer@killercom
		$a_81_4 = {75 6e 6c 6f 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 2e 6c 6e 6b } //20 unlock your files.lnk
		$a_81_5 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //20 vssadmin delete shadows /all /quiet
		$a_81_6 = {2e 73 69 63 6b } //3 .sick
		$a_81_7 = {4c 6e 4e 76 64 6d 6c 6c 64 41 } //3 LnNvdmlldA
		$a_81_8 = {77 68 61 74 5f 68 61 70 70 65 6e 65 64 5f 74 6f 5f 6d 79 5f 6d 75 73 69 63 2e 74 78 74 } //3 what_happened_to_my_music.txt
		$a_81_9 = {45 6e 63 72 79 70 74 69 6f 6e 20 4b 65 79 } //1 Encryption Key
		$a_81_10 = {46 69 6c 65 45 6e 63 72 79 70 74 69 6f 6e } //1 FileEncryption
		$a_81_11 = {45 6e 63 72 79 70 74 65 64 4b 65 79 } //1 EncryptedKey
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*50+(#a_81_3  & 1)*20+(#a_81_4  & 1)*20+(#a_81_5  & 1)*20+(#a_81_6  & 1)*3+(#a_81_7  & 1)*3+(#a_81_8  & 1)*3+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=74
 
}