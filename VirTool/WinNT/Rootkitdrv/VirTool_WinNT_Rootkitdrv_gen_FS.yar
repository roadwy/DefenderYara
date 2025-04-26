
rule VirTool_WinNT_Rootkitdrv_gen_FS{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FS,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 45 fc 83 7d fc 00 0f 8c ?? ?? ?? ?? 83 7d 08 05 0f 85 ?? ?? ?? ?? 8b 4d 0c 89 4d f4 c7 45 f8 00 00 00 00 } //10
		$a_02_1 = {83 7d f4 00 0f 84 ?? ?? ?? ?? 8b 55 f4 83 7a 3c 00 0f 84 ?? ?? ?? ?? b9 0c 00 00 00 bf 80 04 01 00 8b 45 f4 8b 70 3c 33 d2 89 55 ec f3 a6 74 08 1b c0 83 d8 ff 89 45 ec } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}