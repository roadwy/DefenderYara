
rule Trojan_Win32_SuspGolang_QK{
	meta:
		description = "Trojan:Win32/SuspGolang.QK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {55 55 49 44 29 2e 55 6e 6d 61 72 73 68 61 6c 42 69 6e 61 72 79 } //1 UUID).UnmarshalBinary
		$a_81_1 = {43 68 6d 6f 64 29 2e } //1 Chmod).
		$a_81_2 = {43 68 6f 77 6e 52 65 71 29 2e } //1 ChownReq).
		$a_81_3 = {29 2e 53 65 74 57 72 69 74 65 44 65 61 64 6c 69 6e 65 } //1 ).SetWriteDeadline
		$a_81_4 = {43 68 6f 77 6e 29 2e } //1 Chown).
		$a_81_5 = {43 68 74 69 6d 65 73 52 65 71 29 2e } //1 ChtimesReq).
		$a_81_6 = {43 75 72 72 65 6e 74 54 6f 6b 65 6e 4f 77 6e 65 72 52 65 71 29 2e } //1 CurrentTokenOwnerReq).
		$a_81_7 = {43 68 74 69 6d 65 73 29 2e } //1 Chtimes).
		$a_81_8 = {4d 65 6d 66 69 6c 65 73 4c 69 73 74 52 65 71 29 2e } //1 MemfilesListReq).
		$a_81_9 = {4d 65 6d 66 69 6c 65 73 41 64 64 52 65 71 29 2e } //1 MemfilesAddReq).
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}