
rule VirTool_Win32_Vetibuz_B_MTB{
	meta:
		description = "VirTool:Win32/Vetibuz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6a 04 68 00 10 00 00 68 a0 86 01 00 6a 00 ff 15 } //1
		$a_02_1 = {8b f0 89 8d ?? c8 ff ff [0-05] 85 c9 [0-02] 8d 85 ?? c8 ff ff 50 68 a0 86 01 00 56 53 [0-02] 85 c0 [0-02] 8b 8d ?? c8 ff ff } //1
		$a_02_2 = {61 70 69 2e [0-05] 67 69 74 68 [0-03] 75 62 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}