
rule VirTool_Win32_Vetibuz_B_MTB{
	meta:
		description = "VirTool:Win32/Vetibuz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6a 04 68 00 10 00 00 68 a0 86 01 00 6a 00 ff 15 } //1
		$a_02_1 = {8b f0 89 8d 90 01 01 c8 ff ff 90 02 05 85 c9 90 02 02 8d 85 90 01 01 c8 ff ff 50 68 a0 86 01 00 56 53 90 02 02 85 c0 90 02 02 8b 8d 90 01 01 c8 ff ff 90 00 } //1
		$a_02_2 = {61 70 69 2e 90 02 05 67 69 74 68 90 02 03 75 62 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}