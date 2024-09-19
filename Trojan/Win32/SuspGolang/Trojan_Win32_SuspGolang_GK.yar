
rule Trojan_Win32_SuspGolang_GK{
	meta:
		description = "Trojan:Win32/SuspGolang.GK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {4d 65 6d 66 69 6c 65 73 41 64 64 52 65 71 29 2e } //1 MemfilesAddReq).
		$a_81_1 = {4d 65 6d 66 69 6c 65 73 41 64 64 29 2e } //1 MemfilesAdd).
		$a_81_2 = {4d 65 6d 66 69 6c 65 73 52 6d 52 65 71 29 2e } //1 MemfilesRmReq).
		$a_81_3 = {4d 65 6d 66 69 6c 65 73 52 6d 29 2e } //1 MemfilesRm).
		$a_81_4 = {53 6f 63 6b 54 61 62 45 6e 74 72 79 5f 53 6f 63 6b 41 64 64 72 29 2e } //1 SockTabEntry_SockAddr).
		$a_81_5 = {50 69 76 6f 74 54 79 70 65 29 2e } //1 PivotType).
		$a_81_6 = {50 65 65 72 46 61 69 6c 75 72 65 54 79 70 65 29 2e } //1 PeerFailureType).
		$a_81_7 = {29 2e 44 65 6c 65 74 65 54 75 6e } //1 ).DeleteTun
		$a_81_8 = {29 2e 44 65 6c 65 74 65 53 65 71 } //1 ).DeleteSeq
		$a_81_9 = {29 2e 56 61 72 54 69 6d 65 44 6f 75 62 6c 65 53 63 61 6c 61 72 42 61 73 65 4d 75 6c 74 } //1 ).VarTimeDoubleScalarBaseMult
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}