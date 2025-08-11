
rule VirTool_Win64_MiniLoader_A{
	meta:
		description = "VirTool:Win64/MiniLoader.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 08 48 8b 45 30 48 8b 10 8b 45 fc 48 01 d0 44 89 ca 31 ca 88 10 48 8b 45 30 48 8b 48 20 8b 55 fc } //1
		$a_01_1 = {8b 55 fc 48 89 d0 48 c1 e0 04 48 29 d0 48 c1 e0 03 48 89 c2 48 8b 45 f0 48 01 c2 0f b6 45 20 88 42 14 8b 55 fc 48 89 d0 48 c1 e0 04 48 29 d0 48 c1 e0 03 48 89 c2 48 8b 45 f0 48 01 d0 c7 40 10 00 00 00 00 83 45 fc 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}