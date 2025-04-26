
rule VirTool_Win64_Vetibuz_A_MTB{
	meta:
		description = "VirTool:Win64/Vetibuz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 b9 04 00 00 00 41 b8 00 10 00 00 ba a0 86 01 00 33 c9 ff 15 } //1
		$a_02_1 = {41 b8 a0 86 01 00 48 8b 95 ?? ?? 00 00 48 8b 8d ?? ?? 00 00 ff 15 ?? ?? ?? ?? 89 85 } //1
		$a_00_2 = {c6 45 2c 76 c6 45 2d 69 c6 45 2e 72 c6 45 2f 75 c6 45 30 73 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}