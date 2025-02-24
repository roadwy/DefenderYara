
rule VirTool_Win64_Shadowdump_A{
	meta:
		description = "VirTool:Win64/Shadowdump.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 48 83 ec 28 b9 20 02 bc 03 e8 ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 4c 8b d1 0f 05 c3 } //1
		$a_01_1 = {4c 8b d1 b8 26 00 00 00 0f 05 c3 4c 8b d1 b8 0f 00 00 00 0f 05 c3 4c 8b d1 b8 55 00 00 00 0f 05 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}