
rule VirTool_Win32_Persibakz_A_MTB{
	meta:
		description = "VirTool:Win32/Persibakz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 85 70 ff ff ff 46 61 69 6c c7 85 74 ff ff ff 65 64 0a 00 8d 95 90 01 04 b8 00 00 00 00 b9 1e 00 00 00 89 d7 f3 ab 8d 85 90 01 04 ba 90 00 } //01 00 
		$a_03_1 = {89 44 24 08 c7 44 24 04 54 a0 40 00 c7 04 24 01 00 00 80 a1 d8 90 01 03 ff 90 00 } //01 00 
		$a_03_2 = {89 54 24 10 c7 44 24 0c 01 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 82 a0 40 00 89 04 24 a1 dc 90 01 03 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}