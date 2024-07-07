
rule VirTool_Win32_VBInject_gen_AX{
	meta:
		description = "VirTool:Win32/VBInject.gen!AX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 44 65 63 72 79 70 74 } //1 CryptDecrypt
		$a_01_1 = {6d 6f 64 43 72 79 70 74 } //1 modCrypt
		$a_01_2 = {6d 6f 64 4d 61 69 6e } //1 modMain
		$a_01_3 = {43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 69 00 63 00 20 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 } //1 Cryptographic Provider
		$a_01_4 = {57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //1 WriteProcessMemory
		$a_01_5 = {5a 00 77 00 55 00 6e 00 6d 00 61 00 70 00 56 00 69 00 65 00 77 00 4f 00 66 00 53 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 ZwUnmapViewOfSection
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}