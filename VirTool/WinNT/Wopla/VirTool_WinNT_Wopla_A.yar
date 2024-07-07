
rule VirTool_WinNT_Wopla_A{
	meta:
		description = "VirTool:WinNT/Wopla.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {2b c2 83 e8 18 89 42 14 c6 42 0c 58 c6 42 0d 68 89 72 0e c6 42 12 50 c6 42 13 e9 8b c2 5f eb 02 } //1
		$a_02_1 = {72 27 83 65 0c 00 85 f6 76 1b ff 37 e8 90 01 02 00 00 83 c7 04 84 c0 74 08 ff 45 0c 39 75 0c 72 ea 39 75 0c 72 04 83 63 18 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}