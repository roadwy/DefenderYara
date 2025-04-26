
rule VirTool_Win32_VBInject_gen_AW{
	meta:
		description = "VirTool:Win32/VBInject.gen!AW,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6c 73 42 6c 6f 77 66 69 73 68 } //1 clsBlowfish
		$a_01_1 = {45 6e 63 72 79 70 74 42 79 74 65 } //1 EncryptByte
		$a_01_2 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
		$a_01_3 = {66 00 6e 00 69 00 2e 00 6e 00 75 00 72 00 6f 00 74 00 75 00 61 00 } //1 fni.nurotua
		$a_01_4 = {42 00 6c 00 6f 00 77 00 66 00 69 00 73 00 68 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 } //1 Blowfish decryption
		$a_01_5 = {50 00 72 00 6f 00 6a 00 65 00 6b 00 74 00 65 00 } //1 Projekte
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}