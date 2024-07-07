
rule VirTool_Win64_Vetibuz_B_MTB{
	meta:
		description = "VirTool:Win64/Vetibuz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 b9 04 00 00 00 41 b8 00 10 00 00 ba a0 86 01 00 33 c9 ff 15 } //1
		$a_02_1 = {41 b8 a0 86 01 00 48 8b 95 90 01 02 00 00 48 8b 8d 90 01 02 00 00 ff 15 90 01 04 89 85 90 00 } //1
		$a_00_2 = {c6 45 28 61 c6 45 29 70 c6 45 2a 69 c6 45 2b 2e c6 45 2c 67 c6 45 2d 69 c6 45 2e 74 c6 45 2f 68 c6 45 30 75 c6 45 31 62 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}