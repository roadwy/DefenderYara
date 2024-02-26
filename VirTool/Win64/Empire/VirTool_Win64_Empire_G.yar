
rule VirTool_Win64_Empire_G{
	meta:
		description = "VirTool:Win64/Empire.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 03 c8 48 8b c1 48 89 85 90 01 02 00 00 48 8b 85 90 01 02 00 00 8b 40 90 01 01 48 83 e8 90 01 01 33 d2 b9 02 90 00 } //01 00 
		$a_03_1 = {48 03 c8 48 8b c1 48 89 85 90 01 02 00 00 48 8b 85 90 01 02 00 00 48 ff c0 90 00 } //01 00 
		$a_03_2 = {40 55 57 48 81 ec 90 01 02 00 00 48 8d 6c 24 90 01 01 48 8d 7c 24 90 01 01 b9 90 01 04 b8 cc cc cc cc f3 ab 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}