
rule Ransom_Win32_Death_DB_MTB{
	meta:
		description = "Ransom:Win32/Death.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {48 65 6c 6c 6f 4b 69 74 74 79 4d 75 74 65 78 } //1 HelloKittyMutex
		$a_81_1 = {72 65 61 64 5f 6d 65 5f 6c 6b 64 2e 74 78 74 } //1 read_me_lkd.txt
		$a_81_2 = {42 2e 63 72 79 70 74 65 64 } //1 B.crypted
		$a_81_3 = {73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 53 68 61 64 6f 77 43 6f 70 79 } //1 select * from Win32_ShadowCopy
		$a_81_4 = {57 69 6e 33 32 5f 53 68 61 64 6f 77 43 6f 70 79 2e 49 44 } //1 Win32_ShadowCopy.ID
		$a_81_5 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_81_6 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 } //1 taskkill.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}