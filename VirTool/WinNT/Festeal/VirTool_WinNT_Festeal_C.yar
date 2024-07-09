
rule VirTool_WinNT_Festeal_C{
	meta:
		description = "VirTool:WinNT/Festeal.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {85 d2 75 02 eb 3d 0f b6 45 30 85 c0 74 0a b8 06 00 00 80 e9 bd 00 00 00 6a 00 6a 00 6a 01 8b 45 24 50 } //1
		$a_02_1 = {8b 45 0c 83 78 04 00 0f 84 87 00 00 00 68 ?? ?? 01 00 8b 45 0c 8b 48 04 51 e8 ?? ?? 00 00 83 c4 08 85 c0 75 6f } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}