
rule Ransom_Win32_Cryptolocker_PDP_MTB{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {57 61 6e 61 43 72 79 70 74 30 72 } //1 WanaCrypt0r
		$a_81_1 = {2e 77 6e 72 79 } //1 .wnry
		$a_81_2 = {57 41 4e 41 43 52 59 } //1 WANACRY
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Ransom_Win32_Cryptolocker_PDP_MTB_2{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 41 6c 6c 20 46 69 6c 65 73 20 45 6e 63 72 79 70 74 65 64 } //1 Your All Files Encrypted
		$a_81_1 = {53 63 6f 72 70 69 6f 6e 45 6e 63 72 79 70 74 69 6f 6e } //1 ScorpionEncryption
		$a_81_2 = {52 65 61 64 2d 4d 65 2d 4e 6f 77 } //1 Read-Me-Now
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Ransom_Win32_Cryptolocker_PDP_MTB_3{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {46 49 4c 45 53 20 45 4e 43 52 59 50 54 45 44 } //1 FILES ENCRYPTED
		$a_81_1 = {54 6f 75 63 68 4d 65 4e 6f 74 } //1 TouchMeNot
		$a_81_2 = {52 45 43 59 43 4c 45 52 5c 5f 5f 65 6d 70 74 79 } //1 RECYCLER\__empty
		$a_81_3 = {53 79 73 74 65 6d 20 56 6f 6c 75 6d 65 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 5c 5f 5f 65 6d 70 74 79 } //1 System Volume Information\__empty
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_Win32_Cryptolocker_PDP_MTB_4{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 51 75 69 65 74 } //1 vssadmin.exe delete shadows /all /Quiet
		$a_81_1 = {45 4e 43 52 59 50 54 45 44 5f 45 58 54 45 4e 54 49 4f 4e } //1 ENCRYPTED_EXTENTION
		$a_81_2 = {45 4e 43 52 59 50 54 5f 4b 45 59 } //1 ENCRYPT_KEY
		$a_81_3 = {44 45 43 52 59 50 54 } //1 DECRYPT
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_Win32_Cryptolocker_PDP_MTB_5{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 71 75 69 65 74 20 2f 61 6c 6c } //1 /c vssadmin.exe delete shadows /quiet /all
		$a_81_1 = {42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 } //1 BEGIN PUBLIC KEY
		$a_81_2 = {42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 } //1 BEGIN RSA PRIVATE KEY
		$a_81_3 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //1 GetLogicalDrives
		$a_81_4 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 57 } //1 FindFirstFileW
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Ransom_Win32_Cryptolocker_PDP_MTB_6{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_81_1 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //1 DisableRegistryTools
		$a_81_2 = {53 65 61 72 63 68 20 46 69 6c 65 20 55 73 69 6e 67 20 45 78 74 65 6e 73 69 6f 6e } //1 Search File Using Extension
		$a_81_3 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //1 GetTempPathA
		$a_81_4 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 41 } //1 FindNextFileA
		$a_81_5 = {53 48 45 6d 70 74 79 52 65 63 79 63 6c 65 42 69 6e 41 } //1 SHEmptyRecycleBinA
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}