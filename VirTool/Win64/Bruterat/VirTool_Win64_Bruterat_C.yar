
rule VirTool_Win64_Bruterat_C{
	meta:
		description = "VirTool:Win64/Bruterat.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 83 c1 01 48 39 c8 74 17 80 39 ?? 75 f2 } //1
		$a_03_1 = {0f b7 c8 83 c0 ?? 45 0f b6 04 09 0f b7 ca 83 c2 ?? 44 88 44 0c 20 66 41 39 c2 77 e4 } //1
		$a_03_2 = {66 45 85 d2 74 21 31 d2 31 c0 ?? 0f b7 c8 83 c0 ?? 45 0f b6 04 09 0f b7 ca 83 c2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}