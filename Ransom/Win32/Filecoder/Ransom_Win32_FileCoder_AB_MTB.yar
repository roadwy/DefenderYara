
rule Ransom_Win32_FileCoder_AB_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4d 75 73 69 63 5c 6b 65 79 2e 74 78 74 } //01 00  C:\Users\Public\Music\key.txt
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //01 00  Your files have been encrypted!
		$a_01_2 = {44 65 63 72 79 70 74 69 6e 67 20 66 69 6c 65 73 } //01 00  Decrypting files
		$a_01_3 = {49 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 73 65 6e 64 } //00 00  If you want to decrypt your files, send
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_FileCoder_AB_MTB_2{
	meta:
		description = "Ransom:Win32/FileCoder.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 41 4e 53 4f 4d 57 41 52 45 5f 4b 44 46 5f 49 4e 46 4f } //01 00  RANSOMWARE_KDF_INFO
		$a_81_1 = {4e 55 56 44 3d } //01 00  NUVD=
		$a_81_2 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //01 00  expand 32-byte k
		$a_81_3 = {52 45 41 44 4d 45 5f 65 6e 63 72 79 70 74 65 64 2e 74 78 74 } //01 00  README_encrypted.txt
		$a_81_4 = {55 6e 61 62 6c 65 20 74 6f 20 65 6e 63 72 79 70 74 } //01 00  Unable to encrypt
		$a_81_5 = {73 72 63 2f 62 69 6e 2f 72 61 6e 73 6f 6d 77 61 72 65 2e 72 73 } //01 00  src/bin/ransomware.rs
		$a_81_6 = {4c 61 7a 79 20 69 6e 73 74 61 6e 63 65 20 68 61 73 20 70 72 65 76 69 6f 75 73 6c 79 20 62 65 65 6e 20 70 6f 69 73 6f 6e 65 64 } //01 00  Lazy instance has previously been poisoned
		$a_81_7 = {41 54 54 45 4e 54 49 4f 4e 21 21 21 20 41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //01 00  ATTENTION!!! ALL YOUR FILES HAVE BEEN ENCRYPTED
		$a_81_8 = {59 4f 55 20 48 41 56 45 20 54 4f 20 50 41 59 20 24 31 30 30 30 20 44 4f 4c 4c 41 52 53 20 54 4f 20 55 4e 4c 4f 43 4b 20 59 4f 55 52 20 46 49 4c 45 53 } //00 00  YOU HAVE TO PAY $1000 DOLLARS TO UNLOCK YOUR FILES
		$a_00_9 = {5d 04 00 00 } //76 51 
	condition:
		any of ($a_*)
 
}