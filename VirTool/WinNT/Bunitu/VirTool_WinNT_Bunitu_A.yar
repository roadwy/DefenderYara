
rule VirTool_WinNT_Bunitu_A{
	meta:
		description = "VirTool:WinNT/Bunitu.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {80 3a b8 7c 1b 0f b6 52 01 bb ?? ?? 01 00 83 3d ?? ?? 01 00 00 75 09 87 1c 90 90 89 1d ?? ?? 01 00 b8 ?? ?? 01 00 8b 40 01 8b 30 8b d6 bf ?? ?? 01 00 b9 0d 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}