
rule VirTool_WinNT_Pitou_B{
	meta:
		description = "VirTool:WinNT/Pitou.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 00 58 c6 41 09 68 66 c7 41 0e 50 e9 } //1
		$a_01_1 = {8a 11 32 d0 88 17 8a d0 d0 ea 02 c0 32 d0 } //1
		$a_03_2 = {66 c1 c1 08 0f b7 c9 81 e9 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 83 e9 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}