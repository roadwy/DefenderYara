
rule VirTool_Win32_VBInject_gen_FI{
	meta:
		description = "VirTool:Win32/VBInject.gen!FI,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 00 76 00 69 00 6c 00 44 00 72 00 61 00 67 00 6f 00 6e 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 00 00 } //1
		$a_01_1 = {49 00 6e 00 63 00 6f 00 72 00 72 00 65 00 63 00 74 00 20 00 73 00 69 00 7a 00 65 00 20 00 64 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 6f 00 72 00 20 00 69 00 6e 00 20 00 47 00 6f 00 73 00 74 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 } //1 Incorrect size descriptor in Gost decryption
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}