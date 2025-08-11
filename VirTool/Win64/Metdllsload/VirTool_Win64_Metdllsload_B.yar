
rule VirTool_Win64_Metdllsload_B{
	meta:
		description = "VirTool:Win64/Metdllsload.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 0d d1 ?? 00 00 48 8b ?? 83 e0 07 [0-10] 30 04 ?? 48 ff ?? 48 3b } //1
		$a_01_1 = {48 c7 44 24 28 00 00 00 00 89 44 24 20 45 33 c9 33 d2 48 c7 c1 ff ff ff ff 41 b8 40 00 00 00 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}