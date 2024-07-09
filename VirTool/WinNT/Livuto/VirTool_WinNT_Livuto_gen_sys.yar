
rule VirTool_WinNT_Livuto_gen_sys{
	meta:
		description = "VirTool:WinNT/Livuto.gen!sys,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 05 00 00 "
		
	strings :
		$a_03_0 = {7e 13 8a 14 06 80 fa 22 74 06 80 ea ?? 88 14 06 46 3b f1 7c ed } //3
		$a_01_1 = {3d 24 0c 0b 83 0f 84 } //1
		$a_01_2 = {61 75 74 6f 6c 69 76 65 2e 70 64 62 00 } //1
		$a_01_3 = {52 6f 6f 74 6b 69 74 3a 20 4f 6e 55 6e 6c 6f 61 64 } //1 Rootkit: OnUnload
		$a_01_4 = {7e 13 8a 0c 02 84 c9 74 0c fe c1 88 0c 02 42 3b 54 24 08 7c ed c2 08 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}