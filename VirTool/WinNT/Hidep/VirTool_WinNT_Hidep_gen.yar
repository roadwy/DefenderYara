
rule VirTool_WinNT_Hidep_gen{
	meta:
		description = "VirTool:WinNT/Hidep!gen,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {3d 68 50 41 47 75 ed 80 7e 03 45 75 e7 4e b1 04 e8 90 01 0a 3d 44 55 4d 50 0f 85 90 01 04 b1 1c e8 90 01 14 50 50 0f 01 44 24 02 90 01 1b eb 06 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}