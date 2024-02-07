
rule Ransom_MSIL_CryptoLocker_DG_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //01 00  YOUR FILES HAVE BEEN ENCRYPTED
		$a_81_1 = {53 74 61 72 74 45 6e 63 72 79 70 74 69 6f 6e 50 72 6f 63 65 73 73 } //01 00  StartEncryptionProcess
		$a_81_2 = {4e 61 6d 61 73 74 65 55 6e 6c 6f 63 6b } //01 00  NamasteUnlock
		$a_81_3 = {46 69 6c 65 45 6e 63 72 79 70 74 } //00 00  FileEncrypt
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_CryptoLocker_DG_MTB_2{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,38 00 38 00 0a 00 00 28 00 "
		
	strings :
		$a_81_0 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //0a 00  DisableTaskMgr
		$a_81_1 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //0a 00  DisableRegistryTools
		$a_81_2 = {52 61 6e 73 6f 6d 20 2d 20 42 61 63 6b 75 70 } //0a 00  Ransom - Backup
		$a_81_3 = {41 64 61 6d 20 4c 6f 63 6b 65 72 } //05 00  Adam Locker
		$a_81_4 = {44 69 73 61 62 6c 65 4c 6f 63 6b 57 6f 72 6b 73 74 61 74 69 6f 6e } //05 00  DisableLockWorkstation
		$a_81_5 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //05 00  bytesToBeEncrypted
		$a_81_6 = {45 6e 63 72 79 70 74 69 6f 6e 20 43 6f 6d 70 6c 65 74 65 } //01 00  Encryption Complete
		$a_81_7 = {4c 65 67 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Legion.Properties.Resources
		$a_81_8 = {46 72 69 64 61 79 50 72 6f 6a 65 63 74 } //01 00  FridayProject
		$a_81_9 = {61 64 6d 5f 36 34 } //00 00  adm_64
	condition:
		any of ($a_*)
 
}