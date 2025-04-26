
rule VirTool_Win32_VBInject_gen_Q{
	meta:
		description = "VirTool:Win32/VBInject.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {66 58 fc fb 01 04 e4 fc f5 04 00 00 00 04 e8 fc 6c 90 fd f5 08 00 00 00 aa 6c fc fd 0a 09 00 14 00 3c 6c e8 fc 6c 64 fe aa 71 9c fd 04 ec fc 6c 00 fe 0a 0d 00 08 00 3c 6c 00 fe 0a 0e 00 04 00 3c 14 } //1
		$a_00_1 = {63 00 61 00 72 00 62 00 30 00 6e 00 20 00 63 00 72 00 79 00 70 00 74 00 65 00 72 00 } //1 carb0n crypter
		$a_01_2 = {43 61 6c 6c 41 50 49 62 79 4e 61 6d 65 } //1 CallAPIbyName
		$a_01_3 = {52 75 6e 50 45 } //1 RunPE
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}