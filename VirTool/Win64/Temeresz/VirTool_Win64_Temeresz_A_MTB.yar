
rule VirTool_Win64_Temeresz_A_MTB{
	meta:
		description = "VirTool:Win64/Temeresz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 44 24 50 48 8d 90 01 05 e8 90 01 04 48 8d 90 01 05 e8 90 01 04 45 33 c9 48 8d 90 01 05 45 33 c0 41 90 01 03 ff 15 90 00 } //1
		$a_03_1 = {48 8b cb ff 15 90 01 04 85 ff 90 01 02 ff 15 90 01 04 48 85 c0 90 01 02 48 90 01 04 48 8b c8 ff 15 90 01 04 39 90 00 } //1
		$a_03_2 = {4c 89 a4 24 80 02 00 00 4c 8d 90 01 05 90 01 02 81 fb a5 00 00 00 90 01 02 48 8d 90 01 05 e8 90 01 04 33 f6 8d 90 01 02 ff 15 90 01 04 0f b7 f8 8d 90 01 02 c1 ef 0f 83 e7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}