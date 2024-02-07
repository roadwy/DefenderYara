
rule Ransom_MSIL_Cryptolocker_PDQ_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {57 68 61 74 20 68 61 70 70 65 6e 20 74 6f 20 6d 79 20 66 69 6c 65 73 } //01 00  What happen to my files
		$a_81_1 = {54 72 75 6d 70 4c 6f 63 6b 65 72 } //01 00  TrumpLocker
		$a_81_2 = {52 61 6e 73 6f 6d 4e 6f 74 65 } //00 00  RansomNote
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDQ_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 75 6d 6d 79 52 61 6e 73 6f 6d } //01 00  DummyRansom
		$a_81_1 = {65 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //01 00  encryptDirectory
		$a_81_2 = {41 45 53 5f 45 6e 63 72 79 70 74 } //01 00  AES_Encrypt
		$a_81_3 = {2e 6c 6f 63 6b 65 64 } //00 00  .locked
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDQ_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  Files has been encrypted
		$a_81_1 = {41 45 53 5f 45 6e 63 72 79 70 74 } //01 00  AES_Encrypt
		$a_81_2 = {62 69 74 63 6f 69 6e 73 } //01 00  bitcoins
		$a_81_3 = {45 6e 63 72 79 70 74 46 69 6c 65 } //00 00  EncryptFile
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDQ_MTB_4{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {49 27 6d 20 72 75 6e 6e 69 6e 67 20 69 6e 20 44 65 62 75 67 20 6d 6f 64 65 } //01 00  I'm running in Debug mode
		$a_81_1 = {45 78 74 65 6e 73 69 6f 6e 73 54 6f 45 6e 63 72 79 70 74 } //01 00  ExtensionsToEncrypt
		$a_81_2 = {4a 69 67 73 61 77 52 61 6e 73 6f 6d 77 61 72 65 } //00 00  JigsawRansomware
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDQ_MTB_5{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 46 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 73 79 73 74 65 6d 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  All Files on your system has been encrypted
		$a_81_1 = {2e 48 41 4e 54 41 } //01 00  .HANTA
		$a_81_2 = {42 54 43 20 77 61 6c 6c 65 74 3a } //00 00  BTC wallet:
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDQ_MTB_6{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {57 69 6e 33 32 5f 53 68 61 64 6f 77 43 6f 70 79 } //01 00  Win32_ShadowCopy
		$a_81_1 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 4e 61 6d 65 } //01 00  EncryptedFileName
		$a_81_2 = {45 6e 63 72 79 70 74 65 64 4b 65 79 } //01 00  EncryptedKey
		$a_81_3 = {43 6f 75 6c 64 20 6e 6f 74 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 20 63 6f 70 79 } //01 00  Could not delete shadow copy
		$a_81_4 = {4f 50 45 4e 5f 4d 45 5f 54 4f 5f 52 45 53 54 4f 52 45 } //00 00  OPEN_ME_TO_RESTORE
	condition:
		any of ($a_*)
 
}