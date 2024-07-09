
rule VirTool_Win32_Hepenshellz_B_MTB{
	meta:
		description = "VirTool:Win32/Hepenshellz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 45 d0 50 68 dc ?? ?? ?? 8b 4d ac 51 ff 15 ?? ?? ?? ?? 3b f4 } //1
		$a_02_1 = {c7 45 88 00 00 00 00 8b f4 8d ?? ?? 50 8b 4d 94 51 ff } //1
		$a_02_2 = {8b 85 4c ff ff ff 03 85 58 ff ff ff 50 8b 8d 4c ff ff ff 51 83 ec 0c 8b f4 89 a5 20 fe ff ff 8d ?? ?? ?? ?? ?? 52 } //1
		$a_00_3 = {50 8b 85 28 ff ff ff 50 8b 8d 04 ff ff ff 51 e8 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}