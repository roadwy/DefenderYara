
rule VirTool_WinNT_Rootkitdrv_LQ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 6d f4 04 00 61 25 0f 84 ?? ?? ?? ?? 83 6d f4 04 74 ?? 83 6d f4 04 74 } //1
		$a_03_1 = {8b 45 18 8b 40 04 33 d2 6a 14 59 f7 f1 89 45 ?? 8b 45 28 89 45 ?? 83 65 ?? 00 eb 07 8b 45 ?? 40 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 83 ?? ?? 00 00 83 3d ?? ?? ?? ?? 00 74 ?? 8b 45 ?? 6b c0 14 8b 4d ?? 8b 44 01 0c 3b 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}