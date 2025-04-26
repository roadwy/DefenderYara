
rule VirTool_Win32_Sespawnz_A_MTB{
	meta:
		description = "VirTool:Win32/Sespawnz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 18 89 44 24 14 8b 45 14 89 44 24 10 c7 44 24 0c 00 00 00 00 8b 45 10 89 44 24 08 8b 45 08 89 44 24 04 8b 45 0c 89 04 24 a1 70 e1 40 00 ff ?? 83 ec 2c 89 } //1
		$a_03_1 = {89 d0 c1 e8 02 89 de 89 c1 f3 a5 c7 44 24 18 c2 00 00 00 8d 44 ?? ?? 89 44 24 14 c7 44 24 10 00 00 00 00 c7 44 24 0c 98 a0 40 00 c7 44 24 08 d8 a0 40 00 c7 44 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}