
rule VirTool_Win32_VBInject_gen_JL{
	meta:
		description = "VirTool:Win32/VBInject.gen!JL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {07 00 01 00 (90 09 0b 00 c7 84 24|90 09 0a 00 c7 85) } //1
		$a_03_1 = {0b c0 74 02 ff e0 68 ?? ?? 40 00 b8 ?? ?? 40 00 ff d0 ff e0 } //1
		$a_00_2 = {64 6f 61 6e 64 77 69 61 64 6e 69 6f } //1 doandwiadnio
		$a_00_3 = {41 43 54 49 56 45 53 4b 49 4e 4c 69 62 43 74 6c 2e 53 6b 69 6e } //1 ACTIVESKINLibCtl.Skin
		$a_00_4 = {2e 00 76 00 62 00 70 00 } //1 .vbp
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}