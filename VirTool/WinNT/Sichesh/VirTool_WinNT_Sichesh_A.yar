
rule VirTool_WinNT_Sichesh_A{
	meta:
		description = "VirTool:WinNT/Sichesh.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 69 38 31 36 39 2e 70 64 62 00 } //1
		$a_00_1 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 4d 00 53 00 43 00 48 00 45 00 43 00 4b 00 00 00 } //1
		$a_03_2 = {b9 17 c0 20 04 3b c1 0f 87 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 2d 07 c0 20 04 0f 84 ?? ?? ?? ?? 83 e8 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}