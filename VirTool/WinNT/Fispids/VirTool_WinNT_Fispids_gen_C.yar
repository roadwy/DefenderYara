
rule VirTool_WinNT_Fispids_gen_C{
	meta:
		description = "VirTool:WinNT/Fispids.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 45 dc e9 2b c7 83 e8 05 89 45 dd 90 02 01 6a 05 57 8d 45 dc 50 e8 90 01 02 ff ff 33 ff eb 1b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}