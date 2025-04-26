
rule VirTool_WinNT_Rootkitdrv_GI{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.GI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 f9 10 24 08 00 0f ?? ?? 00 00 00 81 f9 08 20 22 00 0f ?? ?? 00 00 00 81 f9 17 e4 22 00 0f ?? ?? 00 00 00 } //1
		$a_03_1 = {03 00 12 00 89 45 ?? 0f 85 ?? ?? 00 00 85 c0 0f 8c ?? ?? 00 00 57 6a 05 59 8d 7d ?? f3 a5 81 7d ?? 00 04 00 00 0f 85 28 01 00 00 83 7d ?? 00 0f 85 ?? ?? 00 00 81 7d ?? 00 02 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}