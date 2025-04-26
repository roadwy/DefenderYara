
rule VirTool_Win32_HeavGatez_B_MTB{
	meta:
		description = "VirTool:Win32/HeavGatez.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {8b 0d 50 b2 41 00 89 41 56 89 51 5a a1 50 b2 41 00 83 c0 6c 8b 0d 50 b2 41 00 89 41 66 8b f4 ff } //1
		$a_00_1 = {8b 0d 50 b2 41 00 89 41 12 89 51 16 8b 45 10 33 c9 8b 15 50 b2 41 00 } //1
		$a_00_2 = {a1 50 b2 41 00 03 45 d8 8b 4d d8 8a 91 60 b0 41 00 88 10 eb dc } //1
		$a_00_3 = {52 50 6a 07 8b 45 d4 50 8b 4d d0 51 e8 } //1
		$a_02_4 = {6a 64 6a 00 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 8b f4 8d 85 ?? ?? ?? ?? 50 68 04 01 00 00 ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}