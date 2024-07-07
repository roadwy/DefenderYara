
rule VirTool_WinNT_Knockex_D{
	meta:
		description = "VirTool:WinNT/Knockex.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 "
		
	strings :
		$a_02_0 = {80 39 e8 75 90 01 01 90 03 01 01 8b ff 90 02 03 8d 54 0a 05 81 3a 58 83 c0 03 75 90 01 01 90 03 01 01 8b ff 90 02 03 eb 90 01 01 81 3a 58 ff 30 60 75 90 01 01 90 03 01 01 8b ff 90 02 03 eb 02 eb 0b c6 01 e9 2b d1 83 ea 05 89 51 01 90 00 } //3
		$a_02_1 = {66 81 38 ff 25 75 90 01 01 90 03 01 01 8b ff 90 00 } //1
		$a_00_2 = {8d 45 9c 50 ff 75 a0 68 30 80 12 00 } //1
	condition:
		((#a_02_0  & 1)*3+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}