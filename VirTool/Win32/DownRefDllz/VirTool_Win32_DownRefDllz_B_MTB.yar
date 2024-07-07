
rule VirTool_Win32_DownRefDllz_B_MTB{
	meta:
		description = "VirTool:Win32/DownRefDllz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 70 00 42 00 8b 45 e8 50 8b 4d d0 51 e8 } //1
		$a_02_1 = {8b f4 8d 85 90 01 04 50 8d 8d 90 01 04 51 6a 00 6a 02 68 78 ff 41 00 68 90 01 01 ff 41 00 68 02 00 00 80 ff 90 00 } //1
		$a_00_2 = {89 85 b0 fd ff ff 8b 85 b0 fd ff ff 89 85 f4 f7 ff ff 81 bd f4 f7 ff ff 6f 07 00 00 74 21 } //1
		$a_02_3 = {8b f4 8d 45 90 01 01 50 8b 4d c0 51 8b 55 a8 52 8b 85 78 ff ff ff 50 ff 90 00 } //1
		$a_00_4 = {6a 00 0f b7 45 0c 50 8b 4d 08 51 8b 55 90 52 ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}