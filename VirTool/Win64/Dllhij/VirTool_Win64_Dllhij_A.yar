
rule VirTool_Win64_Dllhij_A{
	meta:
		description = "VirTool:Win64/Dllhij.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 68 01 00 00 00 48 b8 34 12 6f 5e 4d 3c 2b 1a ff d0 } //1
		$a_01_1 = {56 57 48 89 c7 48 81 c6 c2 05 00 00 48 b9 12 00 00 00 00 00 00 00 f3 a4 5f 5e 4c 89 68 08 48 31 c9 66 41 8b 0f 48 8b 45 10 48 29 c8 49 89 c4 49 89 cd } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}