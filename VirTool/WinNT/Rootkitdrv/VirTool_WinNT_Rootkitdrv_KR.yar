
rule VirTool_WinNT_Rootkitdrv_KR{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 40 0c 3d 24 0c 0b 83 74 ?? 3d 28 0c 0b 83 74 } //1
		$a_03_1 = {8b 44 24 04 3b 05 ?? ?? ?? ?? 7c 07 b8 20 16 01 00 eb 08 6b c0 64 05 ?? ?? ?? ?? c2 04 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}