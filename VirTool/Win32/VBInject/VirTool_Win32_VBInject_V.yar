
rule VirTool_Win32_VBInject_V{
	meta:
		description = "VirTool:Win32/VBInject.V,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 00 43 00 72 00 79 00 70 00 74 00 6f 00 2e 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 } //1 CCrypto.EncryptDecrypt
		$a_01_1 = {53 00 74 00 61 00 6e 00 64 00 61 00 72 00 64 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 20 00 2f 00 76 00 20 00 22 00 44 00 6f 00 4e 00 6f 00 74 00 41 00 6c 00 6c 00 6f 00 77 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 73 00 } //1 StandardProfile /v "DoNotAllowExceptions
		$a_01_2 = {53 00 74 00 61 00 6e 00 64 00 61 00 72 00 64 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 5c 00 41 00 75 00 74 00 68 00 6f 00 72 00 69 00 7a 00 65 00 64 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 4c 00 69 00 73 00 74 00 } //1 StandardProfile\AuthorizedApplications\List
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}