
rule VirTool_Win64_Releposesz_A_MTB{
	meta:
		description = "VirTool:Win64/Releposesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ba d0 20 2e d0 b9 ed b5 d3 22 48 89 c7 e8 90 01 04 48 90 01 04 41 b9 40 00 00 00 4c 90 01 04 49 89 c4 48 89 44 24 50 48 90 01 04 48 c7 c1 ff ff ff ff 48 c7 44 24 58 18 00 00 00 48 89 44 24 20 ff 90 01 01 4c 89 e1 41 b8 18 00 00 00 48 8d 90 00 } //1
		$a_01_1 = {48 c7 40 10 49 ba 00 00 48 89 c3 c7 40 18 00 00 41 ff c6 40 1c e2 48 89 7c 24 60 48 8b 10 48 83 fa 02 } //1
		$a_03_2 = {4c 63 cf 4c 89 e2 48 89 44 24 20 48 8b 05 c8 6c 00 00 4c 89 e9 ff 90 01 01 89 c3 85 c0 0f 84 90 01 04 4c 90 01 04 48 8d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}