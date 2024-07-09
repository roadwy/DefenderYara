
rule VirTool_WinNT_Hackdef_DA{
	meta:
		description = "VirTool:WinNT/Hackdef.DA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {be 00 40 00 00 d1 e6 56 6a 00 e8 ?? ?? ?? ?? 85 c0 74 28 89 45 fc 6a 00 56 50 ff 75 08 ff 15 ?? ?? ?? ?? a9 00 00 00 c0 74 16 3d 04 00 00 c0 75 0a ff 75 fc e8 ?? ?? ?? ?? eb ca 6a 00 8f 45 fc 8b 45 fc 5e c9 c2 04 00 } //1
		$a_01_1 = {68 f1 03 00 00 5b b8 00 00 23 fa ba 9e f8 3a 63 bf c1 a3 81 34 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}