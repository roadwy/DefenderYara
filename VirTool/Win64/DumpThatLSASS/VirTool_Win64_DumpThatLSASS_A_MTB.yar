
rule VirTool_Win64_DumpThatLSASS_A_MTB{
	meta:
		description = "VirTool:Win64/DumpThatLSASS.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b cf ff 15 b4 53 01 00 4c 89 74 24 30 41 b9 ?? 00 00 00 8b d0 4c 89 74 24 28 4c 8b c6 4c 89 74 24 20 48 8b cf ff 15 e1 55 01 } //4
		$a_01_1 = {8a 01 3a 04 11 75 0c 48 ff c1 49 ff c8 75 f1 48 33 c0 c3 } //3
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*3) >=7
 
}