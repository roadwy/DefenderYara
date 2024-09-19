
rule Trojan_Win32_SuspGolang_Y{
	meta:
		description = "Trojan:Win32/SuspGolang.Y,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_81_0 = {50 6f 6c 6c 49 6e 74 65 72 76 61 6c 29 2e } //1 PollInterval).
		$a_81_1 = {53 53 48 43 6f 6d 6d 61 6e 64 52 65 71 29 2e } //1 SSHCommandReq).
		$a_81_2 = {52 65 67 69 73 74 65 72 45 78 74 65 6e 73 69 6f 6e 52 65 71 29 2e } //1 RegisterExtensionReq).
		$a_81_3 = {52 65 67 69 73 74 65 72 45 78 74 65 6e 73 69 6f 6e 29 2e } //1 RegisterExtension).
		$a_81_4 = {43 61 6c 6c 45 78 74 65 6e 73 69 6f 6e 52 65 71 29 2e } //1 CallExtensionReq).
		$a_81_5 = {4c 69 73 74 45 78 74 65 6e 73 69 6f 6e 73 52 65 71 29 2e } //1 ListExtensionsReq).
		$a_81_6 = {44 4e 53 53 65 73 73 69 6f 6e 49 6e 69 74 29 2e } //1 DNSSessionInit).
		$a_81_7 = {50 72 6f 63 65 73 73 44 75 6d 70 52 65 71 29 2e } //1 ProcessDumpReq).
		$a_81_8 = {29 2e 47 65 74 4b 70 61 73 73 77 64 53 65 72 76 65 72 73 } //1 ).GetKpasswdServers
		$a_81_9 = {29 2e 57 69 74 68 50 61 73 73 77 6f 72 64 } //1 ).WithPassword
		$a_81_10 = {29 2e 48 61 73 50 61 73 73 77 6f 72 64 } //1 ).HasPassword
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=10
 
}