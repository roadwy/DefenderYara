
rule Ransom_MSIL_Cryptolocker_RM_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {55 6e 6c 6f 63 6b 59 6f 75 72 46 69 6c 65 73 2e 4c 6f 67 69 6e } //01 00  UnlockYourFiles.Login
		$a_81_1 = {44 65 63 72 79 70 74 41 6c 6c 46 69 6c 65 } //01 00  DecryptAllFile
		$a_81_2 = {70 61 73 73 77 6f 72 64 } //01 00  password
		$a_81_3 = {41 45 53 5f 4f 6e 6c 79 5f 44 65 63 72 79 70 74 5f 46 69 6c 65 } //01 00  AES_Only_Decrypt_File
		$a_81_4 = {67 65 74 5f 44 61 72 6b 47 72 61 79 } //01 00  get_DarkGray
		$a_81_5 = {24 38 63 30 31 32 36 34 35 2d 63 63 35 62 2d 34 64 66 66 2d 39 63 31 33 2d 38 31 32 64 37 34 61 62 63 39 62 33 } //01 00  $8c012645-cc5b-4dff-9c13-812d74abc9b3
		$a_81_6 = {55 6e 6c 6f 63 6b 59 6f 75 72 46 69 6c 65 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  UnlockYourFiles.Properties.Resources
	condition:
		any of ($a_*)
 
}