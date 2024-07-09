
rule VirTool_Win32_Obfuscator_AFS{
	meta:
		description = "VirTool:Win32/Obfuscator.AFS,SIGNATURE_TYPE_PEHSTR_EXT,64 00 04 00 05 00 00 "
		
	strings :
		$a_09_0 = {68 2e 64 6c 6c 68 65 6c 33 32 68 6b 65 72 6e 54 8b 85 f0 fd ff ff } //1
		$a_09_1 = {68 6c 6c 6f 63 68 75 61 6c 41 68 56 69 72 74 54 57 } //1 hllochualAhVirtTW
		$a_09_2 = {68 64 50 74 72 68 64 52 65 61 68 49 73 42 61 54 57 } //1 hdPtrhdReahIsBaTW
		$a_0b_3 = {66 83 38 00 74 14 8a 08 80 f9 61 7c 03 80 e9 20 c1 c9 08 ?? ?? ?? ?? ?? eb e6 89 5c 24 1c } //1
		$a_0b_4 = {89 c1 ff b5 e0 fd ff ff [0-06] 67 3f 7a [0-06] 81 fa ?? 22 7a 3f 0f 84 [0-15] 75 2d 68 0f 84 ?? ?? 00 00 [0-04] fa ?? 7b 23 66 } //1
	condition:
		((#a_09_0  & 1)*1+(#a_09_1  & 1)*1+(#a_09_2  & 1)*1+(#a_0b_3  & 1)*1+(#a_0b_4  & 1)*1) >=4
 
}