
rule Ransom_MSIL_Cryptolocker_PDA_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {57 61 6e 6e 61 4c 6f 63 6b 65 72 } //1 WannaLocker
		$a_81_1 = {40 57 61 6e 6e 61 50 65 61 63 65 } //1 @WannaPeace
		$a_81_2 = {6b 65 79 32 2e 69 63 6f } //1 key2.ico
		$a_81_3 = {42 69 74 63 6f 69 6e } //1 Bitcoin
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDA_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 61 73 6f 6d 77 61 72 65 32 2e 30 } //1 Rasomware2.0
		$a_81_1 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_3 = {43 6f 6e 66 75 73 65 72 45 78 } //1 ConfuserEx
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDA_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6c 62 43 72 79 20 32 2e 30 } //1 AlbCry 2.0
		$a_81_1 = {41 6c 62 43 72 79 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 AlbCry.g.resources
		$a_81_2 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } //1 EncryptedFiles
		$a_81_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDA_MTB_4{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //1 ALL YOUR FILES ARE ENCRYPTED
		$a_81_1 = {48 6f 77 20 54 6f 20 44 65 63 72 79 70 74 20 46 69 6c 65 73 2e 74 78 74 } //1 How To Decrypt Files.txt
		$a_81_2 = {2e 4c 6f 63 6b } //1 .Lock
		$a_81_3 = {45 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //1 EncryptDirectory
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDA_MTB_5{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {54 61 73 6b 20 4d 61 6e 61 67 65 72 } //1 Task Manager
		$a_81_1 = {45 6e 63 72 79 70 74 46 69 6c 65 73 } //1 EncryptFiles
		$a_81_2 = {47 65 74 42 69 74 63 6f 69 6e 41 64 64 72 65 73 73 } //1 GetBitcoinAddress
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {5f 45 6e 63 72 79 70 74 65 64 24 } //1 _Encrypted$
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Ransom_MSIL_Cryptolocker_PDA_MTB_6{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 41 6c 6c 20 46 69 6c 65 73 20 41 72 65 20 44 65 63 72 79 70 74 65 64 } //1 Your All Files Are Decrypted
		$a_81_1 = {46 75 63 6b 74 68 65 53 79 73 74 65 6d } //1 FucktheSystem
		$a_81_2 = {45 6e 63 72 79 70 74 69 6f 6e 20 43 6f 6d 70 6c 65 74 65 } //1 Encryption Complete
		$a_81_3 = {57 72 6f 6e 67 20 4b 65 79 20 42 69 74 63 68 } //1 Wrong Key Bitch
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDA_MTB_7{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 77 61 72 65 32 2e 30 } //1 Ransomware2.0
		$a_81_1 = {52 61 73 6f 6d 77 61 72 65 32 2e 5f 30 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Rasomware2._0.Properties.Resources
		$a_81_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_81_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDA_MTB_8{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your computer files have been encrypted
		$a_81_1 = {42 69 74 63 6f 69 6e 42 6c 61 63 6b 6d 61 69 6c 65 72 } //1 BitcoinBlackmailer
		$a_81_2 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } //1 EncryptedFiles
		$a_81_3 = {45 78 74 65 6e 73 69 6f 6e 73 54 6f 45 6e 63 72 79 70 74 } //1 ExtensionsToEncrypt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDA_MTB_9{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 vssadmin.exe Delete Shadows /All /Quiet
		$a_81_1 = {2e 5b 43 72 69 6d 73 6f 6e 77 61 72 65 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 68 5d } //1 .[Crimsonware@protonmail.ch]
		$a_81_2 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 files have been encrypted
		$a_81_3 = {49 4e 46 4f 2e 68 74 61 } //1 INFO.hta
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}