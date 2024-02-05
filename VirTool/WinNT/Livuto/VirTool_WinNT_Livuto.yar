
rule VirTool_WinNT_Livuto{
	meta:
		description = "VirTool:WinNT/Livuto,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {eb 04 80 00 90 01 01 40 80 38 00 75 f7 b0 01 c2 04 00 8b 44 24 04 eb 06 66 83 00 90 01 01 40 40 66 83 38 00 75 f4 b0 01 c2 04 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}