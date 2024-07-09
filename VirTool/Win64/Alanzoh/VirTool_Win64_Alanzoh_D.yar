
rule VirTool_Win64_Alanzoh_D{
	meta:
		description = "VirTool:Win64/Alanzoh.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 5e 08 0f b6 14 1a 48 8b 5e 18 30 14 0b 8b 56 08 83 c2 01 89 56 08 8b 4e 20 83 c1 01 89 4e 20 48 39 56 10 } //1
		$a_02_1 = {c7 84 24 c0 00 00 00 18 00 00 00 c7 84 24 d0 00 00 00 01 00 00 00 48 c7 84 24 c8 00 00 00 00 00 00 00 0f 29 b4 24 40 03 00 00 48 8d ?? ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? ?? 45 31 c9 ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}