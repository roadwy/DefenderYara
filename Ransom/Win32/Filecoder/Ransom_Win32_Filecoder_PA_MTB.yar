
rule Ransom_Win32_Filecoder_PA_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PA!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {5c 00 4e 00 61 00 6d 00 65 00 20 00 6f 00 66 00 20 00 79 00 6f 00 75 00 72 00 20 00 65 00 78 00 70 00 6c 00 61 00 69 00 6e 00 2e 00 74 00 78 00 74 00 } //1 \Name of your explain.txt
		$a_01_1 = {5c 00 48 00 6f 00 77 00 5f 00 54 00 6f 00 5f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 5f 00 46 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //1 \How_To_Decrypt_Files.txt
		$a_01_2 = {48 00 69 00 21 00 20 00 79 00 6f 00 75 00 72 00 20 00 69 00 6d 00 70 00 6f 00 72 00 74 00 61 00 6e 00 74 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 77 00 65 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //1 Hi! your important files were encrypted!
		$a_01_3 = {59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 } //1 Your Files Encrypted.
		$a_01_4 = {56 00 69 00 63 00 74 00 69 00 6d 00 20 00 6e 00 61 00 6d 00 65 00 } //1 Victim name
		$a_01_5 = {53 00 70 00 61 00 72 00 74 00 61 00 6e 00 20 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 } //1 Spartan Crypter
		$a_01_6 = {2e 00 63 00 72 00 79 00 70 00 74 00 } //1 .crypt
		$a_01_7 = {2e 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 42 00 79 00 53 00 70 00 61 00 72 00 74 00 61 00 6e 00 37 00 38 00 } //1 .EncryptedBySpartan78
		$a_01_8 = {2f 00 43 00 20 00 63 00 68 00 6f 00 69 00 63 00 65 00 20 00 2f 00 43 00 20 00 59 00 20 00 2f 00 4e 00 20 00 2f 00 44 00 20 00 59 00 20 00 2f 00 54 00 20 00 33 00 20 00 26 00 20 00 44 00 65 00 6c 00 20 00 } //1 /C choice /C Y /N /D Y /T 3 & Del 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=5
 
}