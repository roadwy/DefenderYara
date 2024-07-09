
rule VirTool_Win32_Plashelln_B_MTB{
	meta:
		description = "VirTool:Win32/Plashelln.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6a 04 68 00 10 00 00 8b 45 f8 8b 48 08 51 8b 55 08 52 ff } //1
		$a_02_1 = {8b f4 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b 4d f8 8b 49 08 83 c1 01 33 d2 f7 f1 8b 45 f8 89 50 04 } //1
		$a_02_2 = {8b 45 10 50 8b 4d 0c 51 8b 55 08 8b 42 0c 8b 4d 08 03 41 04 50 e8 ?? ?? ?? ?? 83 c4 0c } //1
		$a_00_3 = {8b 45 08 8b 48 0c 8b 55 08 03 4a 04 89 4d e8 8b f4 6a 00 6a 00 6a 00 8b 45 e8 50 6a 00 6a 00 ff } //1
		$a_02_4 = {8b fc ff 15 ?? ?? ?? ?? 3b fc e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 3b f4 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}