
rule VirTool_Win32_Havokiz_F_MTB{
	meta:
		description = "VirTool:Win32/Havokiz.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b9 0e 00 00 00 52 89 85 4c ff ff ff 89 d8 f3 aa b9 28 00 00 00 ?? ?? ?? f3 aa b9 } //1
		$a_03_1 = {89 f7 f3 aa c7 04 24 00 00 00 00 ff 15 ?? ?? ?? ?? 51 89 c3 } //1
		$a_01_2 = {89 74 24 08 c7 44 24 04 18 00 00 00 89 04 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}