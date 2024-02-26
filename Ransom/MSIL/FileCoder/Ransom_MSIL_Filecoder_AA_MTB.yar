
rule Ransom_MSIL_Filecoder_AA_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 08 00 00 14 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 3a } //01 00  Files encrypted:
		$a_81_1 = {65 6e 63 72 79 70 74 65 64 46 69 6c 65 43 6f 75 6e 74 } //01 00  encryptedFileCount
		$a_81_2 = {45 4e 43 52 59 50 54 45 44 5f 46 49 4c 45 5f 45 58 54 45 4e 53 49 4f 4e } //01 00  ENCRYPTED_FILE_EXTENSION
		$a_81_3 = {65 6e 63 72 79 70 74 46 6f 6c 64 65 72 43 6f 6e 74 65 6e 74 73 } //14 00  encryptFolderContents
		$a_81_4 = {45 6e 43 72 79 70 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  EnCrypt.Properties.Resources
		$a_81_5 = {45 6e 43 72 79 70 74 2e 70 64 62 } //01 00  EnCrypt.pdb
		$a_81_6 = {45 6e 63 72 79 70 74 50 68 6f 6e 65 } //01 00  EncryptPhone
		$a_81_7 = {45 6e 43 72 79 70 74 45 78 65 4e 61 6d 65 } //00 00  EnCryptExeName
	condition:
		any of ($a_*)
 
}