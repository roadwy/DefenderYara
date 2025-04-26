
rule VirTool_Win32_VBInject_gen_EL{
	meta:
		description = "VirTool:Win32/VBInject.gen!EL,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {f5 00 00 00 00 05 ?? 00 22 ?? 00 89 06 00 f4 01 ad e7 fe 64 ?? ?? ?? 01 } //2
		$a_03_1 = {22 02 00 8a ?? 00 f5 ?? ?? 00 00 aa f5 ?? 00 00 00 76 ?? 00 b2 } //1
		$a_03_2 = {aa f5 28 00 90 09 0b 00 22 ?? 00 8a ?? 00 f5 ?? ?? 00 00 ?? ?? ?? ?? 00 00 76 ?? 00 b2 } //1
		$a_03_3 = {f4 00 fb fd 23 ?? ff 2a 31 ?? ff 2f ?? ff 04 ?? ff } //2
		$a_03_4 = {f5 01 00 00 00 04 ?? ?? fd 16 10 00 ?? ff fd fe ?? ff 5e 00 00 04 00 f5 02 00 00 00 c0 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*2+(#a_03_4  & 1)*2) >=7
 
}