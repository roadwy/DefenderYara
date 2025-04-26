
rule VirTool_WinNT_Rootkitdrv_gen_FX{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FX,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 45 08 50 ff ?? ?? ?? ?? ?? 89 45 fc 83 7d fc 00 0f 8c ?? ?? ?? ?? 83 7d 08 05 0f 85 ?? ?? ?? ?? 8b 4d 0c 89 4d f4 c7 45 f8 00 00 00 00 } //10
		$a_02_1 = {8b 45 f4 8b 48 28 03 0d ?? ?? ?? ?? 8b 50 2c 13 15 ?? ?? ?? ?? 8b 45 f4 89 48 28 89 50 2c 8b 4d f4 8b 51 30 03 15 ?? ?? ?? ?? 8b 41 34 13 05 ?? ?? ?? ?? 8b 4d f4 89 51 30 89 41 34 } //10
		$a_00_2 = {8b 55 f4 83 3a 00 74 0d 8b 45 f4 8b 4d 0c 03 08 89 4d 0c eb } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10) >=10
 
}