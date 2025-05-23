
rule VirTool_Win64_CoffLdz_A_MTB{
	meta:
		description = "VirTool:Win64/CoffLdz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {48 89 85 48 04 00 00 48 8b 85 48 04 00 00 8b 40 04 48 6b c0 12 48 8b 8d e8 01 00 00 48 03 c8 48 8b c1 48 89 85 68 04 00 00 48 8b 85 68 04 00 00 } //1
		$a_00_1 = {8b 85 24 05 00 00 48 6b c0 18 48 8b 4d 68 48 8b 44 01 08 48 8b 8d 88 00 00 00 48 03 c8 48 8b c1 48 89 85 e8 04 00 00 8b 85 24 05 00 00 } //1
		$a_02_2 = {41 b8 20 00 00 00 48 8b 95 68 01 00 00 48 8b 8d 48 01 00 00 ff 15 ?? ?? ?? ?? 48 8b 85 28 01 00 00 48 89 44 24 28 } //1
		$a_00_3 = {8b 45 24 48 6b c0 12 48 8b 4d 08 48 03 c8 48 8b c1 48 89 45 48 c7 45 64 00 00 00 00 48 c7 85 88 00 00 00 00 00 00 00 b8 01 00 00 00 } //1
		$a_00_4 = {48 c7 45 08 00 00 00 00 41 b8 08 00 00 00 48 8b 95 00 01 00 00 48 8d 4d 08 e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}