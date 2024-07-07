
rule VirTool_WinNT_Rootkitdrv_LJ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 0a ff 71 0c ff 71 08 ff 71 04 52 50 e8 90 01 04 8b f8 33 c0 85 f6 74 0a 0f b6 06 3d b8 00 00 00 74 90 01 01 83 7d 14 00 75 90 01 01 33 c0 90 00 } //1
		$a_03_1 = {ff d7 84 c0 74 90 01 01 8b 46 08 0f b7 08 51 8d 8d 90 01 04 51 ff 70 04 e8 90 01 04 8d 85 90 01 04 68 90 01 04 50 ff 15 90 01 04 85 c0 59 59 75 90 14 b8 22 00 00 c0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}