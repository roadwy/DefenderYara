
rule VirTool_Win64_Metdllsload_A{
	meta:
		description = "VirTool:Win64/Metdllsload.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b c2 83 e0 07 42 0f b6 04 00 30 04 11 48 ff c2 48 3b d7 } //1
		$a_01_1 = {48 c7 44 24 28 00 00 00 00 89 44 24 20 45 33 c9 33 d2 48 c7 c1 ff ff ff ff 41 b8 40 00 00 00 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}