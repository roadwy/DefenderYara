
rule VirTool_Win32_VBInject_gen_MP{
	meta:
		description = "VirTool:Win32/VBInject.gen!MP,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 05 00 00 "
		
	strings :
		$a_03_0 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 66 33 0c 50 ff 15 } //1
		$a_03_1 = {0b c0 74 02 ff e0 68 ?? ?? 40 00 b8 ?? ?? 40 00 ff d0 ff e0 } //1
		$a_03_2 = {43 61 6c 6c 57 69 6e 64 6f 77 50 72 6f 63 [0-60] 0b c0 74 02 ff e0 } //1
		$a_01_3 = {42 69 74 65 72 6f 70 65 73 74 } //1 Biteropest
		$a_01_4 = {4d 65 74 65 72 6f 6c 6f 62 } //1 Meterolob
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=50
 
}