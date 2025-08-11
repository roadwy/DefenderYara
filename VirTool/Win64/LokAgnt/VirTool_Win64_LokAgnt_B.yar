
rule VirTool_Win64_LokAgnt_B{
	meta:
		description = "VirTool:Win64/LokAgnt.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 48 61 c6 44 24 49 6d c6 44 24 4a 73 c6 44 24 4b 69 c6 44 24 4c 2e c6 44 24 4d 64 c6 44 24 4e 6c c6 44 24 4f 6c c6 44 24 50 00 c6 44 24 78 90 c6 44 24 79 90 c6 44 24 7a 90 c6 44 24 7b b8 c6 44 24 7c 57 c6 44 24 7d 00 c6 44 24 7e 07 c6 44 24 7f 80 c6 84 24 80 00 00 00 c3 } //1
		$a_02_1 = {00 00 b8 01 00 00 00 90 09 03 00 e8 } //1
		$a_01_2 = {81 38 50 45 00 00 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}