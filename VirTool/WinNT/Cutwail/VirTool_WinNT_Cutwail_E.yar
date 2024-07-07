
rule VirTool_WinNT_Cutwail_E{
	meta:
		description = "VirTool:WinNT/Cutwail.E,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 7d ff ff ff 0f b7 c0 83 f8 19 74 28 83 f8 50 74 23 3d e8 03 00 00 72 07 3d b8 0b 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}