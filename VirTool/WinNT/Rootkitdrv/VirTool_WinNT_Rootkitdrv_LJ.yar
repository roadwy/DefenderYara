
rule VirTool_WinNT_Rootkitdrv_LJ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 0a ff 71 0c ff 71 08 ff 71 04 52 50 e8 ?? ?? ?? ?? 8b f8 33 c0 85 f6 74 0a 0f b6 06 3d b8 00 00 00 74 ?? 83 7d 14 00 75 ?? 33 c0 } //1
		$a_03_1 = {ff d7 84 c0 74 ?? 8b 46 08 0f b7 08 51 8d 8d ?? ?? ?? ?? 51 ff 70 04 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 85 c0 59 59 75 90 14 b8 22 00 00 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}