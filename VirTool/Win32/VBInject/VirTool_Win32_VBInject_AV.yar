
rule VirTool_Win32_VBInject_AV{
	meta:
		description = "VirTool:Win32/VBInject.AV,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 00 6c 00 6f 00 77 00 66 00 69 00 73 00 68 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 } //1 Blowfish decryption
		$a_01_1 = {32 00 33 00 6c 00 65 00 6e 00 72 00 65 00 6b 00 } //1 23lenrek
		$a_01_2 = {53 00 65 00 74 00 54 00 68 00 72 00 65 00 61 00 64 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 } //1 SetThreadContext
		$a_01_3 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //5 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5) >=9
 
}