
rule VirTool_Win32_VBInject_gen_AZ{
	meta:
		description = "VirTool:Win32/VBInject.gen!AZ,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 46 69 6c 65 } //3 EncryptFile
		$a_01_1 = {57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //3 WriteProcessMemory
		$a_01_2 = {53 00 65 00 74 00 54 00 68 00 72 00 65 00 61 00 64 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 } //3 SetThreadContext
		$a_01_3 = {32 00 33 00 6c 00 65 00 6e 00 72 00 65 00 6b 00 } //3 23lenrek
		$a_01_4 = {54 00 45 00 41 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 } //1 TEA decryption
		$a_01_5 = {42 00 6c 00 6f 00 77 00 66 00 69 00 73 00 68 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 } //1 Blowfish decryption
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}