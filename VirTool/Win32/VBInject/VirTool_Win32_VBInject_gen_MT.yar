
rule VirTool_Win32_VBInject_gen_MT{
	meta:
		description = "VirTool:Win32/VBInject.gen!MT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e0 72 ff fb 11 e7 6c 6c ff f5 26 00 00 00 0b 00 00 04 00 23 58 ff f5 48 00 00 00 0b 00 00 04 00 23 54 ff 2a 23 50 ff f5 46 00 00 00 0b 00 00 04 00 23 4c ff 2a 23 48 ff } //1
		$a_00_1 = {4e 00 65 00 72 00 69 00 6f 00 70 00 65 00 72 00 74 00 5c 00 4b 00 6f 00 6c 00 69 00 64 00 65 00 72 00 74 00 2e 00 76 00 62 00 70 00 } //1 Neriopert\Kolidert.vbp
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}