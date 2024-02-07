
rule Trojan_Win32_Omaneat_MS_MTB{
	meta:
		description = "Trojan:Win32/Omaneat.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 01 00 "
		
	strings :
		$a_81_0 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //01 00  \Google\Chrome\User Data
		$a_81_1 = {5c 57 61 6c 6c 65 74 73 } //01 00  \Wallets
		$a_81_2 = {44 52 49 56 45 5f 52 45 4d 4f 56 41 42 4c 45 } //01 00  DRIVE_REMOVABLE
		$a_81_3 = {4c 4f 43 41 4c 41 50 50 44 41 54 41 } //01 00  LOCALAPPDATA
		$a_81_4 = {66 69 6c 65 73 5c 69 6e 66 6f 72 6d 61 74 69 6f 6e 2e 74 78 74 } //01 00  files\information.txt
		$a_81_5 = {5c 76 63 72 75 6e 74 69 6d 65 31 34 30 2e 64 6c 6c } //01 00  \vcruntime140.dll
		$a_81_6 = {73 6f 66 74 6f 6b 6e 33 2e 64 6c 6c } //01 00  softokn3.dll
		$a_81_7 = {4d 65 74 61 4d 61 73 6b } //01 00  MetaMask
		$a_81_8 = {5c 4c 6f 63 61 6c 20 45 78 74 65 6e 73 69 6f 6e 20 53 65 74 74 69 6e 67 73 } //01 00  \Local Extension Settings
		$a_81_9 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //01 00  CreateDirectoryA
		$a_81_10 = {44 65 6c 65 74 65 46 69 6c 65 57 } //01 00  DeleteFileW
		$a_81_11 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 57 } //01 00  FindFirstFileW
		$a_81_12 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 41 } //00 00  FindNextFileA
	condition:
		any of ($a_*)
 
}