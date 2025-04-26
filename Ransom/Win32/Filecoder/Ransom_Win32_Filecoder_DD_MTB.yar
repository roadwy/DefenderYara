
rule Ransom_Win32_Filecoder_DD_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 Your files are encrypted
		$a_81_1 = {41 6c 6c 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 66 6f 72 20 74 68 69 73 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 65 78 74 65 6e 73 69 6f 6e 3a 20 2e 39 34 36 35 62 62 } //1 All encrypted files for this computer has extension: .9465bb
		$a_81_2 = {52 65 62 6f 6f 74 69 6e 67 2f 73 68 75 74 64 6f 77 6e 20 77 69 6c 6c 20 63 61 75 73 65 20 79 6f 75 20 74 6f 20 6c 6f 73 65 20 66 69 6c 65 73 20 77 69 74 68 6f 75 74 20 74 68 65 20 70 6f 73 73 69 62 69 6c 69 74 79 20 6f 66 20 72 65 63 6f 76 65 72 79 } //1 Rebooting/shutdown will cause you to lose files without the possibility of recovery
		$a_81_3 = {4a 75 73 74 20 6f 70 65 6e 20 6f 75 72 20 77 65 62 73 69 74 65 2c 20 75 70 6c 6f 61 64 20 74 68 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 20 61 6e 64 20 67 65 74 20 74 68 65 20 64 65 63 72 79 70 74 65 64 20 66 69 6c 65 20 66 6f 72 20 66 72 65 65 } //1 Just open our website, upload the encrypted file and get the decrypted file for free
		$a_03_4 = {4f 70 65 6e 20 6f 75 72 20 77 65 62 73 69 74 65 3a 20 [0-3c] 2e 6f 6e 69 6f 6e } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}
rule Ransom_Win32_Filecoder_DD_MTB_2{
	meta:
		description = "Ransom:Win32/Filecoder.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 6c 69 6b 65 20 70 68 6f 74 6f 73 2c 20 64 61 74 61 62 61 73 65 73 2c 20 64 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 6f 74 68 65 72 20 69 6d 70 6f 72 74 61 6e 74 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 73 74 72 6f 6e 67 65 73 74 20 65 6e 63 72 79 70 74 69 6f 6e 20 61 6e 64 20 75 6e 69 71 75 65 20 6b 65 79 } //1 All your files like photos, databases, documents and other important are encrypted with strongest encryption and unique key
		$a_81_1 = {54 68 65 20 6f 6e 6c 79 20 6d 65 74 68 6f 64 20 6f 66 20 72 65 63 6f 76 65 72 69 6e 67 20 66 69 6c 65 73 20 69 73 20 74 6f 20 70 75 72 63 68 61 73 65 20 64 65 63 72 79 70 74 20 74 6f 6f 6c 20 61 6e 64 20 75 6e 69 71 75 65 20 6b 65 79 20 66 6f 72 20 79 6f 75 } //1 The only method of recovering files is to purchase decrypt tool and unique key for you
		$a_81_2 = {59 6f 75 20 63 61 6e 20 73 65 6e 64 20 6f 6e 65 20 6f 66 20 79 6f 75 72 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 20 66 72 6f 6d 20 79 6f 75 72 20 50 43 20 61 6e 64 20 77 65 20 64 65 63 72 79 70 74 20 69 74 20 66 6f 72 20 66 72 65 65 } //1 You can send one of your encrypted file from your PC and we decrypt it for free
		$a_81_3 = {50 6c 65 61 73 65 20 6e 6f 74 65 20 74 68 61 74 20 79 6f 75 27 6c 6c 20 6e 65 76 65 72 20 72 65 73 74 6f 72 65 20 79 6f 75 72 20 64 61 74 61 20 77 69 74 68 6f 75 74 20 70 61 79 6d 65 6e 74 } //1 Please note that you'll never restore your data without payment
		$a_81_4 = {72 65 73 74 6f 72 65 6d 61 6e 61 67 65 72 40 61 69 72 6d 61 69 6c 2e 63 63 } //1 restoremanager@airmail.cc
		$a_81_5 = {68 74 74 70 73 3a 2f 2f 77 65 2e 74 6c 2f 74 2d 63 63 55 66 55 72 51 4f 68 46 } //1 https://we.tl/t-ccUfUrQOhF
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=3
 
}
rule Ransom_Win32_Filecoder_DD_MTB_3{
	meta:
		description = "Ransom:Win32/Filecoder.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_81_0 = {41 4c 4c 20 59 4f 55 52 20 44 4f 43 55 4d 45 4e 54 53 20 50 48 4f 54 4f 53 20 44 41 54 41 42 41 53 45 53 20 41 4e 44 20 4f 54 48 45 52 20 49 4d 50 4f 52 54 41 4e 54 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //1 ALL YOUR DOCUMENTS PHOTOS DATABASES AND OTHER IMPORTANT FILES HAVE BEEN ENCRYPTED
		$a_81_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 4e 4f 54 20 64 61 6d 61 67 65 64 21 20 59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 6d 6f 64 69 66 69 65 64 20 6f 6e 6c 79 2e 20 54 68 69 73 20 6d 6f 64 69 66 69 63 61 74 69 6f 6e 20 69 73 20 72 65 76 65 72 73 69 62 6c 65 } //1 Your files are NOT damaged! Your files are modified only. This modification is reversible
		$a_81_2 = {54 68 65 20 6f 6e 6c 79 20 31 20 77 61 79 20 74 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 69 73 20 74 6f 20 72 65 63 65 69 76 65 20 74 68 65 20 70 72 69 76 61 74 65 20 6b 65 79 20 61 6e 64 20 64 65 63 72 79 70 74 69 6f 6e 20 70 72 6f 67 72 61 6d } //1 The only 1 way to decrypt your files is to receive the private key and decryption program
		$a_81_3 = {41 6e 79 20 61 74 74 65 6d 70 74 73 20 74 6f 20 72 65 73 74 6f 72 65 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 74 68 20 74 68 65 20 74 68 69 72 64 20 70 61 72 74 79 20 73 6f 66 74 77 61 72 65 20 77 69 6c 6c 20 62 65 20 66 61 74 61 6c 20 66 6f 72 20 79 6f 75 72 20 66 69 6c 65 73 } //1 Any attempts to restore your files with the third party software will be fatal for your files
		$a_81_4 = {54 6f 20 72 65 63 65 69 76 65 20 74 68 65 20 70 72 69 76 61 74 65 20 6b 65 79 20 61 6e 64 20 64 65 63 72 79 70 74 69 6f 6e 20 70 72 6f 67 72 61 6d 20 66 6f 6c 6c 6f 77 20 74 68 65 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 20 62 65 6c 6f 77 } //1 To receive the private key and decryption program follow the instructions below
		$a_03_5 = {68 74 74 70 3a 2f 2f [0-1e] 2e [0-14] 2e 6f 6e 69 6f 6e 2f } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_03_5  & 1)*1) >=3
 
}