
rule VirTool_WinNT_Tedroo_gen_A{
	meta:
		description = "VirTool:WinNT/Tedroo.gen!A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 0c c7 45 f8 02 00 00 c0 e9 d0 00 00 00 8d 45 ec 50 ff 75 08 53 6a 0b ff d6 85 c0 89 45 f8 0f 85 b9 00 00 00 } //1
		$a_01_1 = {80 3e b8 75 07 8b 76 01 89 31 eb 05 b8 02 00 00 c0 83 c2 04 83 3a 00 8b ca 75 e3 5e c2 04 00 55 8b ec 83 ec 14 a1 18 15 01 00 0f b7 00 3d 93 08 00 00 } //1
		$a_01_2 = {57 8b c6 e8 bb fb ff ff 83 c4 04 84 c0 74 19 e8 6f fc ff ff 84 c0 74 05 e8 e6 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}