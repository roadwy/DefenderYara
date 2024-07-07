
rule VirTool_Win32_Excheposez_A_MTB{
	meta:
		description = "VirTool:Win32/Excheposez.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 00 00 00 00 33 c0 0f 11 45 d0 c7 45 e0 00 00 00 00 c7 45 e4 07 00 00 00 66 89 45 d0 90 01 03 c6 45 fc 01 50 90 01 03 50 6a 01 6a 00 90 01 06 33 f6 85 c0 90 00 } //1
		$a_03_1 = {68 00 01 00 00 50 90 01 06 50 90 01 05 68 00 01 00 00 90 01 06 6a 00 50 90 01 05 83 c4 18 c7 85 d0 bd ff ff 00 00 00 00 6a 03 90 02 12 50 6a 01 68 ff 01 0f 00 90 01 06 50 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}