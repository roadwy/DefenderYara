
rule VirTool_Win32_Filnesez_A_MTB{
	meta:
		description = "VirTool:Win32/Filnesez.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b f0 85 f6 90 01 02 68 00 00 06 00 6a 00 6a 00 68 44 c6 43 00 ff 15 90 01 04 8b f8 85 ff 74 2f 8b d7 8b ce e8 90 01 04 56 ff 15 90 01 04 57 ff 15 90 00 } //1
		$a_03_1 = {c6 45 fc 01 8b cf e8 90 01 04 83 c4 18 8b f0 ba a4 cc 43 00 b9 70 42 44 00 e8 90 01 04 57 8b c8 e8 24 90 00 } //1
		$a_03_2 = {c6 45 fc 00 e8 90 01 04 83 c4 18 8b c8 e8 90 01 04 56 6a 00 6a 00 6a ff 6a 00 89 46 04 ff 15 90 01 04 85 c0 90 01 02 68 a4 d9 43 00 68 b4 d9 43 00 ff 15 90 01 04 50 ff 15 90 00 } //1
		$a_03_3 = {c6 45 fc 08 ba c0 cc 43 00 b9 70 42 44 00 e8 90 01 04 8d 90 01 02 8b c8 e8 90 01 04 50 e8 90 01 04 83 c4 08 e8 90 01 04 8d 90 01 02 8d 90 01 02 e8 9a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}