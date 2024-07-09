
rule VirTool_Win32_CoffLdz_B_MTB{
	meta:
		description = "VirTool:Win32/CoffLdz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b f4 8d 85 ?? ?? ?? ?? 50 6a 20 8b 8d 6c ff ff ff 51 8b 95 7c ff ff ff 52 ff } //1
		$a_02_1 = {8b f4 6a 04 68 00 30 10 00 8b 45 ac b9 08 00 00 00 f7 e1 50 6a 00 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 89 45 c4 83 7d c4 00 } //1
		$a_00_2 = {8b 55 08 52 8b 45 14 50 8b 4d 10 51 8b 55 0c 52 e8 } //1
		$a_00_3 = {a1 58 d2 41 00 89 45 f8 8b 45 08 8b 0d 5c d2 41 00 89 08 c7 05 58 d2 41 00 00 00 00 00 c7 05 5c d2 41 00 00 00 00 00 c7 05 60 d2 41 00 00 00 00 00 8b 45 f8 } //1
		$a_00_4 = {8b 45 f8 0f b7 48 02 39 4d ec 73 3a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}