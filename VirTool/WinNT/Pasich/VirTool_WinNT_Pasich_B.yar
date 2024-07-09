
rule VirTool_WinNT_Pasich_B{
	meta:
		description = "VirTool:WinNT/Pasich.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 31 30 44 54 6a 30 6a 00 ff 15 ?? ?? ?? ?? 89 45 fc 83 7d fc 00 75 07 } //1
		$a_03_1 = {57 8d 7d f1 c6 45 f0 e9 ab 8b 7d 08 57 e8 ?? ?? 00 00 89 45 14 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}