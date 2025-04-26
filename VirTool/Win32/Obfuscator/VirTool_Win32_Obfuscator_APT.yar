
rule VirTool_Win32_Obfuscator_APT{
	meta:
		description = "VirTool:Win32/Obfuscator.APT,SIGNATURE_TYPE_PEHSTR_EXT,06 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 74 64 6c 6c 2e 64 6c 6c 20 00 00 15 00 00 00 5a 77 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 } //1
		$a_01_1 = {6c 0c 00 43 74 ff 4b 4a 00 6c 74 ff f4 01 f4 ff fe 5d 20 00 f4 01 f4 01 0b 00 00 04 00 e7 04 74 ff f5 00 00 00 00 fc 76 f4 01 fd 3d 6c 74 ff f5 00 00 00 00 fb 3d 1c 3f 00 ff 2f 10 00 02 00 f4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}