
rule Ransom_MSIL_Cryptolocker_PDN_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {69 6e 66 65 63 74 65 64 20 77 69 74 68 20 72 61 6e 73 6f 6d 77 61 72 65 } //01 00  infected with ransomware
		$a_81_1 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 4c 69 73 74 } //01 00  EncryptedFileList
		$a_81_2 = {45 78 74 65 6e 73 69 6f 6e 73 54 6f 45 6e 63 72 79 70 74 } //00 00  ExtensionsToEncrypt
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDN_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00  All your files are encrypted
		$a_81_1 = {44 45 43 52 59 50 54 20 4d 59 20 46 49 4c 45 53 } //01 00  DECRYPT MY FILES
		$a_81_2 = {2f 43 20 73 63 20 64 65 6c 65 74 65 20 56 53 53 } //00 00  /C sc delete VSS
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDN_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {57 6f 72 6b 65 72 43 72 79 70 74 65 72 32 } //01 00  WorkerCrypter2
		$a_81_1 = {53 65 61 72 63 68 46 69 6c 65 73 } //01 00  SearchFiles
		$a_81_2 = {45 6e 63 72 79 70 74 } //01 00  Encrypt
		$a_81_3 = {47 65 6e 65 72 61 74 65 4b 65 79 } //01 00  GenerateKey
		$a_81_4 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_81_5 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  ToBase64String
	condition:
		any of ($a_*)
 
}