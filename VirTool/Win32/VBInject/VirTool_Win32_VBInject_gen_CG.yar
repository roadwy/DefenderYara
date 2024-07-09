
rule VirTool_Win32_VBInject_gen_CG{
	meta:
		description = "VirTool:Win32/VBInject.gen!CG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {94 78 fc 1c 00 94 78 fc 10 00 aa 71 9c fd } //1
		$a_03_1 = {8b 40 1c 03 41 10 [0-06] 89 85 40 fe ff ff } //1
		$a_03_2 = {8b 85 a8 fe ff ff 03 85 b4 fe ff ff [0-0d] 89 85 24 fe ff ff } //1
		$a_02_3 = {38 00 42 00 34 00 43 00 32 00 34 00 30 00 38 00 35 00 31 00 3c 00 [0-20] 3e 00 45 00 38 00 3c 00 [0-20] 3e 00 35 00 39 00 38 00 39 00 30 00 31 00 36 00 36 00 33 00 31 00 43 00 30 00 43 00 33 00 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_02_3  & 1)*3) >=4
 
}