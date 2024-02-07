
rule Ransom_Win64_Filecoder_SS_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.SS!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 5f 5f 52 45 41 44 5f 4d 45 5f 54 4f 5f 52 45 43 4f 56 45 52 5f 59 4f 55 52 5f 46 49 4c 45 53 2e 74 78 74 } //01 00  \__READ_ME_TO_RECOVER_YOUR_FILES.txt
		$a_01_1 = {48 65 6c 6c 6f 2c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 61 72 65 20 63 75 72 72 65 6e 74 6c 79 20 75 6e 75 73 61 62 6c 65 } //01 00  Hello, your files were encrypted and are currently unusable
		$a_01_2 = {42 69 74 63 6f 69 6e 20 77 61 6c 6c 65 74 3a 20 33 39 38 73 57 35 65 4d 44 76 79 72 39 33 43 4a 48 4b 52 44 33 65 59 45 39 76 4b 35 45 4c 56 72 48 50 } //01 00  Bitcoin wallet: 398sW5eMDvyr93CJHKRD3eYE9vK5ELVrHP
		$a_01_3 = {2e 65 6e 63 72 70 } //01 00  .encrp
		$a_01_4 = {43 3a 5c 55 73 65 72 73 5c 4d 41 52 49 4f 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 45 4e 43 52 49 50 54 41 52 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 45 4e 43 52 49 50 54 41 52 2e 70 64 62 } //01 00  C:\Users\MARIO\source\repos\ENCRIPTAR\x64\Release\ENCRIPTAR.pdb
		$a_01_5 = {54 68 65 20 6f 6e 6c 79 20 77 61 79 20 74 6f 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 20 69 73 20 64 65 63 72 79 70 74 69 6e 67 20 74 68 65 6d 20 77 69 74 68 20 61 20 6b 65 79 20 74 68 61 74 20 6f 6e 6c 79 20 77 65 20 68 61 76 65 } //01 00  The only way to recover your files is decrypting them with a key that only we have
		$a_01_6 = {49 6e 20 6f 72 64 65 72 20 66 6f 72 20 75 73 20 74 6f 20 73 65 6e 64 20 79 6f 75 20 74 68 65 20 6b 65 79 20 61 6e 64 20 74 68 65 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 74 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 79 6f 75 20 77 69 6c 6c 20 68 61 76 65 20 74 6f 20 6d 61 6b 65 20 61 20 74 72 61 6e 73 66 65 72 20 6f 66 20 42 69 74 63 6f 69 6e 73 } //00 00  In order for us to send you the key and the application to decrypt your files, you will have to make a transfer of Bitcoins
	condition:
		any of ($a_*)
 
}