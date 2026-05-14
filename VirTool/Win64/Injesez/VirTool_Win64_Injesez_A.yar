
rule VirTool_Win64_Injesez_A{
	meta:
		description = "VirTool:Win64/Injesez.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e0 05 48 63 c8 48 03 cb 80 39 4c ?? ?? 80 79 01 8b ?? ?? 80 79 02 d1 ?? ?? 80 79 03 b8 } //1
		$a_03_1 = {4c 89 6c 24 70 48 c7 45 60 00 10 00 00 c7 44 24 28 40 00 00 00 c7 44 24 20 00 30 00 00 ?? ?? ?? ?? 45 33 c0 ?? ?? ?? ?? ?? 48 8b ce e8 ?? ?? ?? ?? 85 c0 ?? ?? 8b d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}