
rule VirTool_WinNT_Fispids_gen_A{
	meta:
		description = "VirTool:WinNT/Fispids.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 45 dc e9 2b ca 83 e9 05 89 4d dd 6a 05 52 8d 45 dc 50 e8 90 01 02 ff ff 33 ff eb 1b 90 00 } //01 00 
		$a_03_1 = {c6 45 d4 e9 2b c6 83 e8 05 89 45 d5 6a 05 56 8d 45 d4 50 e8 90 01 02 ff ff 33 f6 eb 1b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}