
rule VirTool_Win64_Amsipatch_D_MTB{
	meta:
		description = "VirTool:Win64/Amsipatch.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 31 c0 90 90 } //1
		$a_02_1 = {41 b9 04 00 00 00 48 89 44 24 20 4c 8d 90 01 03 48 c7 44 24 40 00 10 00 00 48 8d 90 01 03 48 89 5c 24 30 48 8b ce ff 15 90 00 } //1
		$a_02_2 = {48 c7 44 24 20 00 00 00 00 4c 8d 90 01 03 48 8b d3 48 8b ce ff 15 90 00 } //1
		$a_02_3 = {44 8b 4c 24 38 48 8d 90 01 03 4c 8d 90 01 03 48 89 44 24 20 48 8d 90 01 03 48 8b ce ff 15 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}