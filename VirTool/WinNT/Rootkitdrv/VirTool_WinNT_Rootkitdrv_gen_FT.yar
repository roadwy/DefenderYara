
rule VirTool_WinNT_Rootkitdrv_gen_FT{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FT,SIGNATURE_TYPE_PEHSTR_EXT,15 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 44 24 0c 8b 08 8b d1 83 ea 00 74 19 4a 74 0f 51 68 90 01 04 e8 90 01 04 59 59 eb 16 90 00 } //0a 00 
		$a_00_1 = {ff b0 d4 07 00 00 83 c0 04 50 } //01 00 
		$a_00_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 6d 00 73 00 69 00 6f 00 73 00 44 00 6f 00 6d 00 33 00 32 00 } //01 00 
		$a_00_3 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 6d 00 73 00 69 00 6f 00 73 00 44 00 6f 00 6d 00 33 00 32 00 } //00 00 
	condition:
		any of ($a_*)
 
}