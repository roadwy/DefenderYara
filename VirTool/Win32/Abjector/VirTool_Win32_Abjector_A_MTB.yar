
rule VirTool_Win32_Abjector_A_MTB{
	meta:
		description = "VirTool:Win32/Abjector.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {cc 55 8b ec [0-08] 64 [0-02] 30 00 00 00 [0-0e] 8b ?? 0c 83 ?? 0c } //1
		$a_00_1 = {c1 c0 07 8d 52 01 0f be c9 33 c1 8a 0a 84 c9 } //1
		$a_02_2 = {6a 40 68 00 30 00 00 [0-07] ff ?? 50 [0-08] 6a 00 89 45 ?? ff } //1
		$a_00_3 = {b8 4d 5a 00 00 66 39 } //1
		$a_02_4 = {6a 01 6a 01 ?? 03 ?? ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}