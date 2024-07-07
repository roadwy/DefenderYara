
rule HackTool_Win64_Hacktheworld_G_MTB{
	meta:
		description = "HackTool:Win64/Hacktheworld.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_02_0 = {74 0a b8 00 00 00 00 e9 90 01 01 01 00 00 e8 90 04 01 03 40 2d 44 ff ff ff 85 c0 0f 84 90 01 01 01 00 00 90 00 } //2
		$a_02_1 = {b9 00 e1 f5 05 e8 90 01 01 16 00 00 90 00 } //2
		$a_02_2 = {76 a4 41 b9 40 00 00 00 41 b8 00 10 00 00 ba 90 01 03 00 b9 00 00 00 00 48 8b 05 90 01 03 00 ff d0 90 02 99 41 b9 00 00 00 00 49 89 c0 ba 00 00 00 00 b9 00 00 00 00 48 8b 05 90 01 03 00 ff d0 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2) >=6
 
}