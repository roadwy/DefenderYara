
rule VirTool_Win64_Rovnix_A{
	meta:
		description = "VirTool:Win64/Rovnix.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 3d 46 4a 74 18 66 8b 43 10 48 83 c3 10 66 85 c0 75 ed 66 81 3b 46 4a } //2
		$a_01_1 = {c6 03 68 8b 46 18 89 43 01 c6 43 05 e8 48 8b 46 10 48 2b c3 48 83 e8 0a 89 43 06 eb 04 } //1
		$a_01_2 = {48 85 c9 74 08 4d 85 c9 74 0e 49 ff e1 4d 85 c0 74 06 48 8b ca 49 ff e0 b8 0d 00 00 c0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}