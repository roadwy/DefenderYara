
rule VirTool_Win64_Kilebesz_A{
	meta:
		description = "VirTool:Win64/Kilebesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 4c 24 08 55 53 56 57 41 55 ?? ?? ?? ?? ?? 48 81 ec c0 00 00 00 b9 20 00 00 00 49 8b f0 48 8b da e8 ?? ?? ?? ?? 48 8b f8 45 33 ed ?? ?? ?? ?? ?? ?? ?? 48 8b cf 48 89 07 } //1
		$a_03_1 = {48 63 41 04 48 8b 4c 30 48 48 8b 01 41 b8 21 00 00 00 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? 48 83 f8 21 ?? ?? ba 04 00 00 00 8b fa 89 54 24 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}