
rule VirTool_WinNT_Rootkitdrv_BU{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.BU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8d 7e 38 f3 ab b8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 46 48 89 46 44 c7 46 70 ?? ?? ?? ?? c7 46 34 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 53 53 8d 45 f8 50 8d 45 fc 50 } //1
		$a_00_1 = {c7 45 0c 98 00 00 00 c7 45 fc 88 00 00 00 eb 1e c7 45 0c a0 00 00 00 c7 45 fc fc 01 00 00 eb 0e c7 45 0c 88 00 00 00 c7 45 fc 74 01 00 00 8b 45 0c 8d 0c 30 39 09 89 4d f8 74 56 8b d1 2b 55 0c 33 c0 8d 7d e4 ab ab ab ab aa } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}