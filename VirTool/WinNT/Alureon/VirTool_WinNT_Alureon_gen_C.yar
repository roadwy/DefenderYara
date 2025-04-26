
rule VirTool_WinNT_Alureon_gen_C{
	meta:
		description = "VirTool:WinNT/Alureon.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_0b_0 = {81 f2 20 83 b8 ed 89 55 f8 eb 03 d1 6d f8 ff 4d ?? 75 ?? 8b 55 f8 89 94 85 a0 fb ff ff 40 3d 00 01 00 00 7c ?? 83 c8 ff 0f b6 11 ff 4d f4 33 d0 81 e2 ff 00 00 00 c1 e8 08 33 84 95 a0 fb ff ff 41 83 7d f4 00 75 e1 f7 d0 3b 45 ?? 74 08 ff 45 ?? e9 ?? ?? ?? ?? 6a 14 ff 75 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? 8b 45 14 8b 40 1c 85 c0 74 0f 6a 00 6a 14 8d 4d ?? 51 ff d0 } //1
	condition:
		((#a_0b_0  & 1)*1) >=1
 
}