
rule VirTool_Win32_CeeInject_SD_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SD!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 0f 8b c1 33 d2 5f f7 f7 8a 82 90 01 04 30 81 90 01 04 41 3b ce 72 e6 90 00 } //01 00 
		$a_03_1 = {73 09 8b 4d fc 89 0d 90 01 04 8b 0d 90 01 04 8a 18 30 1c 31 03 ce 47 40 46 4a 75 90 00 } //01 00 
		$a_03_2 = {0f b6 4c 24 04 8b c1 03 c9 c1 e8 90 01 01 6b c0 90 01 01 33 c1 c3 90 00 } //01 00 
		$a_03_3 = {57 32 d8 e8 90 01 04 32 d8 a1 90 01 04 32 5d 90 01 01 83 c4 20 32 5d 90 01 01 32 5d 90 01 01 88 1c 06 8b 45 90 01 01 80 b8 90 01 04 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}