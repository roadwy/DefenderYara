
rule VirTool_Win64_Poxetz_A_MTB{
	meta:
		description = "VirTool:Win64/Poxetz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {48 89 c1 41 ff ?? 48 8b 45 a8 48 8b 55 f0 48 89 c1 ff } //1
		$a_00_1 = {48 c7 45 a8 00 00 00 00 48 8d 55 b0 48 8d 45 a8 4c 8b 55 f8 41 b9 00 00 00 00 49 89 d0 } //1
		$a_00_2 = {48 89 d3 48 8b 03 48 8b 4b 08 48 8b 53 10 4d 31 c0 4c 8b 4b 18 4c 8b 53 20 4c 89 54 24 30 41 ba 00 30 00 00 4c 89 54 24 28 ff } //1
		$a_00_3 = {ba 00 10 00 00 48 c7 c1 ff ff ff ff 48 8b 05 5c 89 00 00 ff d0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}