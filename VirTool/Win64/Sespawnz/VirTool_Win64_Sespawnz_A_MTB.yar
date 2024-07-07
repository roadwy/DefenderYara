
rule VirTool_Win64_Sespawnz_A_MTB{
	meta:
		description = "VirTool:Win64/Sespawnz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 f2 48 89 f8 8b 0a 89 08 48 90 01 03 48 90 01 03 0f b6 0a 88 08 48 c7 44 24 30 15 01 00 00 48 90 01 03 48 89 44 24 28 48 c7 44 24 20 00 00 00 00 4c 8d 90 01 05 4c 8d 90 01 05 48 8d 90 01 05 48 90 00 } //1
		$a_03_1 = {48 8b 8d e0 00 00 00 48 89 4c 24 28 48 8b 8d d8 00 00 00 48 89 4c 24 20 41 b9 00 00 00 00 48 89 c1 48 8b 05 de c8 00 00 ff 90 01 01 89 85 98 00 00 00 83 bd 98 00 00 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}